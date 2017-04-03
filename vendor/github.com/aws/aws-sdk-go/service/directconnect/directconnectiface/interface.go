// THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT.

// Package directconnectiface provides an interface to enable mocking the AWS Direct Connect service client
// for testing your code.
//
// It is important to note that this interface will have breaking changes
// when the service model is updated and adds new API operations, paginators,
// and waiters.
package directconnectiface

import (
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/directconnect"
)

// DirectConnectAPI provides an interface to enable mocking the
// directconnect.DirectConnect service client's API operation,
// paginators, and waiters. This make unit testing your code that calls out
// to the SDK's service client's calls easier.
//
// The best way to use this interface is so the SDK's service client's calls
// can be stubbed out for unit testing your code with the SDK without needing
// to inject custom request handlers into the the SDK's request pipeline.
//
//    // myFunc uses an SDK service client to make a request to
//    // AWS Direct Connect.
//    func myFunc(svc directconnectiface.DirectConnectAPI) bool {
//        // Make svc.AllocateConnectionOnInterconnect request
//    }
//
//    func main() {
//        sess := session.New()
//        svc := directconnect.New(sess)
//
//        myFunc(svc)
//    }
//
// In your _test.go file:
//
//    // Define a mock struct to be used in your unit tests of myFunc.
//    type mockDirectConnectClient struct {
//        directconnectiface.DirectConnectAPI
//    }
//    func (m *mockDirectConnectClient) AllocateConnectionOnInterconnect(input *directconnect.AllocateConnectionOnInterconnectInput) (*directconnect.Connection, error) {
//        // mock response/functionality
//    }
//
//    func TestMyFunc(t *testing.T) {
//        // Setup Test
//        mockSvc := &mockDirectConnectClient{}
//
//        myfunc(mockSvc)
//
//        // Verify myFunc's functionality
//    }
//
// It is important to note that this interface will have breaking changes
// when the service model is updated and adds new API operations, paginators,
// and waiters. Its suggested to use the pattern above for testing, or using
// tooling to generate mocks to satisfy the interfaces.
type DirectConnectAPI interface {
	AllocateConnectionOnInterconnectRequest(*directconnect.AllocateConnectionOnInterconnectInput) (*request.Request, *directconnect.Connection)

	AllocateConnectionOnInterconnect(*directconnect.AllocateConnectionOnInterconnectInput) (*directconnect.Connection, error)

	AllocateHostedConnectionRequest(*directconnect.AllocateHostedConnectionInput) (*request.Request, *directconnect.Connection)

	AllocateHostedConnection(*directconnect.AllocateHostedConnectionInput) (*directconnect.Connection, error)

	AllocatePrivateVirtualInterfaceRequest(*directconnect.AllocatePrivateVirtualInterfaceInput) (*request.Request, *directconnect.VirtualInterface)

	AllocatePrivateVirtualInterface(*directconnect.AllocatePrivateVirtualInterfaceInput) (*directconnect.VirtualInterface, error)

	AllocatePublicVirtualInterfaceRequest(*directconnect.AllocatePublicVirtualInterfaceInput) (*request.Request, *directconnect.VirtualInterface)

	AllocatePublicVirtualInterface(*directconnect.AllocatePublicVirtualInterfaceInput) (*directconnect.VirtualInterface, error)

	AssociateConnectionWithLagRequest(*directconnect.AssociateConnectionWithLagInput) (*request.Request, *directconnect.Connection)

	AssociateConnectionWithLag(*directconnect.AssociateConnectionWithLagInput) (*directconnect.Connection, error)

	AssociateHostedConnectionRequest(*directconnect.AssociateHostedConnectionInput) (*request.Request, *directconnect.Connection)

	AssociateHostedConnection(*directconnect.AssociateHostedConnectionInput) (*directconnect.Connection, error)

	AssociateVirtualInterfaceRequest(*directconnect.AssociateVirtualInterfaceInput) (*request.Request, *directconnect.VirtualInterface)

	AssociateVirtualInterface(*directconnect.AssociateVirtualInterfaceInput) (*directconnect.VirtualInterface, error)

	ConfirmConnectionRequest(*directconnect.ConfirmConnectionInput) (*request.Request, *directconnect.ConfirmConnectionOutput)

	ConfirmConnection(*directconnect.ConfirmConnectionInput) (*directconnect.ConfirmConnectionOutput, error)

	ConfirmPrivateVirtualInterfaceRequest(*directconnect.ConfirmPrivateVirtualInterfaceInput) (*request.Request, *directconnect.ConfirmPrivateVirtualInterfaceOutput)

	ConfirmPrivateVirtualInterface(*directconnect.ConfirmPrivateVirtualInterfaceInput) (*directconnect.ConfirmPrivateVirtualInterfaceOutput, error)

	ConfirmPublicVirtualInterfaceRequest(*directconnect.ConfirmPublicVirtualInterfaceInput) (*request.Request, *directconnect.ConfirmPublicVirtualInterfaceOutput)

	ConfirmPublicVirtualInterface(*directconnect.ConfirmPublicVirtualInterfaceInput) (*directconnect.ConfirmPublicVirtualInterfaceOutput, error)

	CreateBGPPeerRequest(*directconnect.CreateBGPPeerInput) (*request.Request, *directconnect.CreateBGPPeerOutput)

	CreateBGPPeer(*directconnect.CreateBGPPeerInput) (*directconnect.CreateBGPPeerOutput, error)

	CreateConnectionRequest(*directconnect.CreateConnectionInput) (*request.Request, *directconnect.Connection)

	CreateConnection(*directconnect.CreateConnectionInput) (*directconnect.Connection, error)

	CreateInterconnectRequest(*directconnect.CreateInterconnectInput) (*request.Request, *directconnect.Interconnect)

	CreateInterconnect(*directconnect.CreateInterconnectInput) (*directconnect.Interconnect, error)

	CreateLagRequest(*directconnect.CreateLagInput) (*request.Request, *directconnect.Lag)

	CreateLag(*directconnect.CreateLagInput) (*directconnect.Lag, error)

	CreatePrivateVirtualInterfaceRequest(*directconnect.CreatePrivateVirtualInterfaceInput) (*request.Request, *directconnect.VirtualInterface)

	CreatePrivateVirtualInterface(*directconnect.CreatePrivateVirtualInterfaceInput) (*directconnect.VirtualInterface, error)

	CreatePublicVirtualInterfaceRequest(*directconnect.CreatePublicVirtualInterfaceInput) (*request.Request, *directconnect.VirtualInterface)

	CreatePublicVirtualInterface(*directconnect.CreatePublicVirtualInterfaceInput) (*directconnect.VirtualInterface, error)

	DeleteBGPPeerRequest(*directconnect.DeleteBGPPeerInput) (*request.Request, *directconnect.DeleteBGPPeerOutput)

	DeleteBGPPeer(*directconnect.DeleteBGPPeerInput) (*directconnect.DeleteBGPPeerOutput, error)

	DeleteConnectionRequest(*directconnect.DeleteConnectionInput) (*request.Request, *directconnect.Connection)

	DeleteConnection(*directconnect.DeleteConnectionInput) (*directconnect.Connection, error)

	DeleteInterconnectRequest(*directconnect.DeleteInterconnectInput) (*request.Request, *directconnect.DeleteInterconnectOutput)

	DeleteInterconnect(*directconnect.DeleteInterconnectInput) (*directconnect.DeleteInterconnectOutput, error)

	DeleteLagRequest(*directconnect.DeleteLagInput) (*request.Request, *directconnect.Lag)

	DeleteLag(*directconnect.DeleteLagInput) (*directconnect.Lag, error)

	DeleteVirtualInterfaceRequest(*directconnect.DeleteVirtualInterfaceInput) (*request.Request, *directconnect.DeleteVirtualInterfaceOutput)

	DeleteVirtualInterface(*directconnect.DeleteVirtualInterfaceInput) (*directconnect.DeleteVirtualInterfaceOutput, error)

	DescribeConnectionLoaRequest(*directconnect.DescribeConnectionLoaInput) (*request.Request, *directconnect.DescribeConnectionLoaOutput)

	DescribeConnectionLoa(*directconnect.DescribeConnectionLoaInput) (*directconnect.DescribeConnectionLoaOutput, error)

	DescribeConnectionsRequest(*directconnect.DescribeConnectionsInput) (*request.Request, *directconnect.Connections)

	DescribeConnections(*directconnect.DescribeConnectionsInput) (*directconnect.Connections, error)

	DescribeConnectionsOnInterconnectRequest(*directconnect.DescribeConnectionsOnInterconnectInput) (*request.Request, *directconnect.Connections)

	DescribeConnectionsOnInterconnect(*directconnect.DescribeConnectionsOnInterconnectInput) (*directconnect.Connections, error)

	DescribeHostedConnectionsRequest(*directconnect.DescribeHostedConnectionsInput) (*request.Request, *directconnect.Connections)

	DescribeHostedConnections(*directconnect.DescribeHostedConnectionsInput) (*directconnect.Connections, error)

	DescribeInterconnectLoaRequest(*directconnect.DescribeInterconnectLoaInput) (*request.Request, *directconnect.DescribeInterconnectLoaOutput)

	DescribeInterconnectLoa(*directconnect.DescribeInterconnectLoaInput) (*directconnect.DescribeInterconnectLoaOutput, error)

	DescribeInterconnectsRequest(*directconnect.DescribeInterconnectsInput) (*request.Request, *directconnect.DescribeInterconnectsOutput)

	DescribeInterconnects(*directconnect.DescribeInterconnectsInput) (*directconnect.DescribeInterconnectsOutput, error)

	DescribeLagsRequest(*directconnect.DescribeLagsInput) (*request.Request, *directconnect.DescribeLagsOutput)

	DescribeLags(*directconnect.DescribeLagsInput) (*directconnect.DescribeLagsOutput, error)

	DescribeLoaRequest(*directconnect.DescribeLoaInput) (*request.Request, *directconnect.Loa)

	DescribeLoa(*directconnect.DescribeLoaInput) (*directconnect.Loa, error)

	DescribeLocationsRequest(*directconnect.DescribeLocationsInput) (*request.Request, *directconnect.DescribeLocationsOutput)

	DescribeLocations(*directconnect.DescribeLocationsInput) (*directconnect.DescribeLocationsOutput, error)

	DescribeTagsRequest(*directconnect.DescribeTagsInput) (*request.Request, *directconnect.DescribeTagsOutput)

	DescribeTags(*directconnect.DescribeTagsInput) (*directconnect.DescribeTagsOutput, error)

	DescribeVirtualGatewaysRequest(*directconnect.DescribeVirtualGatewaysInput) (*request.Request, *directconnect.DescribeVirtualGatewaysOutput)

	DescribeVirtualGateways(*directconnect.DescribeVirtualGatewaysInput) (*directconnect.DescribeVirtualGatewaysOutput, error)

	DescribeVirtualInterfacesRequest(*directconnect.DescribeVirtualInterfacesInput) (*request.Request, *directconnect.DescribeVirtualInterfacesOutput)

	DescribeVirtualInterfaces(*directconnect.DescribeVirtualInterfacesInput) (*directconnect.DescribeVirtualInterfacesOutput, error)

	DisassociateConnectionFromLagRequest(*directconnect.DisassociateConnectionFromLagInput) (*request.Request, *directconnect.Connection)

	DisassociateConnectionFromLag(*directconnect.DisassociateConnectionFromLagInput) (*directconnect.Connection, error)

	TagResourceRequest(*directconnect.TagResourceInput) (*request.Request, *directconnect.TagResourceOutput)

	TagResource(*directconnect.TagResourceInput) (*directconnect.TagResourceOutput, error)

	UntagResourceRequest(*directconnect.UntagResourceInput) (*request.Request, *directconnect.UntagResourceOutput)

	UntagResource(*directconnect.UntagResourceInput) (*directconnect.UntagResourceOutput, error)

	UpdateLagRequest(*directconnect.UpdateLagInput) (*request.Request, *directconnect.Lag)

	UpdateLag(*directconnect.UpdateLagInput) (*directconnect.Lag, error)
}

var _ DirectConnectAPI = (*directconnect.DirectConnect)(nil)