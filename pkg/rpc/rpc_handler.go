// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package rpc

import (
	"context"
	"net"
	"time"

	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/utils"

	"github.com/emilyhuaa/policyLogsEnhancement/pkg/rpc"

	cnirpc "github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	npgRPCaddress         = "127.0.0.1:50052"
	grpcHealthServiceName = "grpc.health.v1.np-agent"
	syncInterval          = 30 * time.Second
)

// server controls RPC service responses.
type server struct {
	policyReconciler *controllers.PolicyEndpointsReconciler
	log              logr.Logger
	metadataCache    map[string]*rpc.Metadata
}

// EnforceNpToPod processes CNI Enforce NP network request
func (s *server) EnforceNpToPod(ctx context.Context, in *cnirpc.EnforceNpRequest) (*cnirpc.EnforceNpReply, error) {
	s.log.Info("Received Enforce Network Policy Request for Pod", "Name", in.K8S_POD_NAME, "Namespace", in.K8S_POD_NAMESPACE)
	var err error

	podIdentifier := utils.GetPodIdentifier(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, s.log)
	isMapUpdateRequired := s.policyReconciler.GeteBPFClient().IsMapUpdateRequired(podIdentifier)
	err = s.policyReconciler.GeteBPFClient().AttacheBPFProbes(types.NamespacedName{Name: in.K8S_POD_NAME, Namespace: in.K8S_POD_NAMESPACE},
		podIdentifier, true, true)
	if err != nil {
		s.log.Error(err, "Attaching eBPF probe failed for", "pod", in.K8S_POD_NAME, "namespace", in.K8S_POD_NAMESPACE)
		return nil, err
	}

	// We attempt to program eBPF firewall map entries for this pod, if the local agent is aware of the policies
	// configured against it. For example, if this is a new replica of an existing pod/deployment then the local
	// node agent will have the policy information available to it. If not, we will leave the pod in default deny state
	// until the Network Policy controller reconciles existing policies against this pod.

	// Check if there are active policies against the new pod and if there are other pods on the local node that share
	// the eBPF firewall maps with the newly launched pod, if already present we can skip the map update and return
	if s.policyReconciler.ArePoliciesAvailableInLocalCache(podIdentifier) && isMapUpdateRequired {
		// If we're here, then the local agent knows the list of active policies that apply to this pod and
		// this is the first pod of it's type to land on the local node/cluster
		s.log.Info("Active policies present against this pod and this is a new Pod to the local node, configuring firewall rules....")

		//Derive Ingress and Egress Firewall Rules and Update the relevant eBPF maps
		ingressRules, egressRules, _ :=
			s.policyReconciler.DeriveFireWallRulesPerPodIdentifier(podIdentifier, in.K8S_POD_NAMESPACE)

		err = s.policyReconciler.GeteBPFClient().UpdateEbpfMaps(podIdentifier, ingressRules, egressRules)
		if err != nil {
			s.log.Error(err, "Map update(s) failed for, ", "podIdentifier ", podIdentifier)
			return nil, err
		}
	} else {
		s.log.Info("Pod either has no active policies or shares the eBPF firewall maps with other local pods. No Map update required..")
	}

	resp := cnirpc.EnforceNpReply{
		Success: err == nil,
	}
	return &resp, nil
}

// GetMetadaCache retrieves the MetadataCache.
func (s *server) GetMetadataCache(ctx context.Context, req *rpc.GetCacheRequest) (*rpc.GetCacheReply, error) {
	entries := make([]*rpc.MetadataCacheEntry, 0, len(s.metadataCache))
	for ip, metadata := range s.metadataCache {
		entry := &rpc.MetadataCacheEntry{
			Ip:       ip,
			Metadata: metadata,
		}
		entries = append(entries, entry)
	}

	reply := &rpc.GetCacheReply{
		Entries: entries,
	}

	return reply, nil
}

// RunRPCHandler handles requests from gRPC
func RunRPCHandler(policyReconciler *controllers.PolicyEndpointsReconciler) error {
	rpcLog := ctrl.Log.WithName("rpc-handler")

	rpcLog.Info("Serving RPC Handler", "Address", npgRPCaddress)
	listener, err := net.Listen("tcp", npgRPCaddress)
	if err != nil {
		rpcLog.Error(err, "Failed to listen gRPC port")
		return errors.Wrap(err, "network policy agent: failed to listen to gRPC port")
	}
	grpcServer := grpc.NewServer()
	s := &server{
		policyReconciler: policyReconciler,
		log:              rpcLog,
		metadataCache:    make(map[string]*rpc.Metadata),
	}
	cnirpc.RegisterNPBackendServer(grpcServer, &server{policyReconciler: policyReconciler, log: rpcLog})
	healthServer := health.NewServer()
	healthServer.SetServingStatus(grpcHealthServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	reflection.Register(grpcServer)

	// Start a goroutine to periodically sync the cache
	go syncCacheLoop(grpcServer, s)

	if err := grpcServer.Serve(listener); err != nil {
		rpcLog.Error(err, "Failed to start server on gRPC port: %v", err)
		return errors.Wrap(err, "network policy agent: failed to start server on gPRC port")
	}
	rpcLog.Info("Done with RPC Handler initialization")
	return nil
}

func syncCacheLoop(server *grpc.Server, s *server) {
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	for range ticker.C {
		UpdateLocalCache(server, s)
	}
}

// UpdateLocalCache updates the local cache with the entries from the server-side cache.
func UpdateLocalCache(server *grpc.Server, s *server) {
	entries, err := s.GetMetadataCache(context.Background(), &rpc.GetCacheRequest{})
	if err != nil {
		ctrl.Log.Error(err, "Failed to get metadata cache from server")
		return
	}

	utils.LocalCacheMutex.Lock()
	defer utils.LocalCacheMutex.Unlock()
	utils.LocalCache = make(map[string][]utils.Metadata)
	for _, entry := range entries.Entries {
		metadata := utils.Metadata{
			Name:      entry.Metadata.Name,
			Namespace: entry.Metadata.Namespace,
		}
		utils.LocalCache[entry.Ip] = append(utils.LocalCache[entry.Ip], metadata)
	}
}
