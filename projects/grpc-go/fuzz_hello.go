package grpc_hello_fuzz

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

var initialized = 0

type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func FuzzHelloServer(data []byte) int {
	if initialized == 0 {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Printf("failed to listen: %v\n", err)
			return 0
		}
		s := grpc.NewServer()
		pb.RegisterGreeterServer(s, &server{})
		// start server as a separate goroutine
		go func() {
			if err := s.Serve(lis); err != nil {
				log.Printf("failed to serve: %v\n", err)
			}
		}()
		initialized = 1
	}

	conn, err := net.Dial("tcp", "localhost:50051")
	if err != nil {
		log.Printf("failed to dial: %v\n", err)
		return 0
	}
	conn.Write(data)
	response := make([]byte, 1+len(data))
	n, err := conn.Read(response)
	conn.Close()
	if err != nil || n == 0 {
		return 0
	}
	return 1
}

var fuzzdata []byte

func FuzzHelloClient(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if initialized == 0 {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Printf("failed to listen: %v\n", err)
			return 0
		}
		go func() {
			for {
				conn, err := lis.Accept()
				if err != nil {
					log.Printf("did not accept: %v", err)
					break
				}
				conn.SetDeadline(time.Now().Add(time.Millisecond * 100))
				request := make([]byte, 24)
				n, err := conn.Read(request)
				if err != nil || n == 0 {
					log.Printf("did not read: %v", err)
					conn.Close()
					break
				}
				n, err = conn.Write(fuzzdata)
				if err != nil || n == 0 {
					log.Printf("did not write: %v", err)
				}
				conn.Close()
			}
		}()
		initialized = 1
	}

	fuzzdata = data
	// Set up a connection to the server.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return 0
	}
	defer conn.Close()
	c := pb.NewGreeterClient(conn)

	// Contact the server and print out its response.
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: "world"})
	if err != nil {
		return 0
	}
	r.GetMessage()
	return 1
}
