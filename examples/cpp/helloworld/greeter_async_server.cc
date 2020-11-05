/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <memory>
#include <iostream>
#include <string>
#include <thread>
#include <sstream>
#include <fstream>

#include <grpcpp/grpcpp.h>
#include <grpc/support/log.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCompletionQueue;
using grpc::Status;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;
/**
 * \brief Represents error codes related to protohead
 */
enum class ProtoheadErrorCode {
    kOK = 0,                  ///< Things looks ok
    kProtoheadFailure = 1,    ///< Some things are not ok
    kProtoheadTlsFailure = 2  ///< Some TLS things are not ok
};

std::error_code make_error_code(ProtoheadErrorCode e);

/**
 * \brief Provides human readable representation of error codes related to protohead
 */
class ProtoheadErrorCategory : public std::error_category {
public:
    const char *name() const noexcept override;

    std::string message(int ev) const override;
};

std::ostream &operator<<(std::ostream &o, ProtoheadErrorCode code);

// -------- impls
const std::error_category& error_category() {
    static ProtoheadErrorCategory instance;
    return instance;
}

std::error_code make_error_code(ProtoheadErrorCode e) {
    return std::error_code(static_cast<int>(e), error_category());
}

const char* ProtoheadErrorCategory::name() const noexcept { return "northguard::protohead::ProtoheadErrorCategory"; }

std::string ProtoheadErrorCategory::message(int ev) const {
    std::stringstream strstream;

    switch (static_cast<ProtoheadErrorCode>(ev)) {
        case ProtoheadErrorCode::kOK:
            strstream << "Protohead status << kOK(" << static_cast<uint16_t>(ProtoheadErrorCode::kOK) << ')';
            return strstream.str();

        case ProtoheadErrorCode::kProtoheadFailure:
            strstream << "Protohead encountered error in Protohead: kProtoheadFailure("
                      << static_cast<uint16_t>(ProtoheadErrorCode::kProtoheadFailure) << ')';
            return strstream.str();

        case ProtoheadErrorCode::kProtoheadTlsFailure:
            strstream << "Protohead encountered error in TLS initialization: kProtoheadTlsFailure("
                      << static_cast<uint16_t>(ProtoheadErrorCode::kProtoheadTlsFailure) << ')';
            return strstream.str();

        default:
            strstream << "Unknown ProtoheadErrorCategory: " << ev;
            return strstream.str();
    }
}

std::ostream& operator<<(std::ostream& o, ProtoheadErrorCode code) {
    o << static_cast<uint8_t>(code);
    return o;
}

std::string ReadFile(const std::string &filename, std::error_code &ec) {
    ec.clear();
    std::ifstream in(filename);
    if (!in) {
        ec = make_error_code(ProtoheadErrorCode::kProtoheadTlsFailure);
        return {};
    }
    std::istreambuf_iterator<char> begin(in), end;
    ec = make_error_code(ProtoheadErrorCode::kOK);
    return std::string(begin, end);
}

grpc::SslCredentialsOptions ReadTlsCredentials(const std::string &tls_private_key_filename,
                                               const std::string &tls_cert_chain_filename,
                                               const std::string &tls_root_certs_filename, std::error_code &ec) {
    ec.clear();
    grpc::SslCredentialsOptions tls_options;

    std::cout << "\nReading private key file: " << tls_private_key_filename;
    tls_options.pem_private_key = ReadFile(tls_private_key_filename, ec);
    if (ec) {
        std::cerr << "Unable to read private key file: " << tls_private_key_filename;
        return {};
    }
    std::cout << "\nReading certificate chain file: " << tls_cert_chain_filename;
    tls_options.pem_cert_chain = ReadFile(tls_cert_chain_filename, ec);
    if (ec) {
        std::cerr << "Unable to read certificate chain file: " << tls_cert_chain_filename;
        return {};
    }
    std::cout << "\nReading root ca certs file: " << tls_root_certs_filename;
    tls_options.pem_root_certs = ReadFile(tls_root_certs_filename, ec);
    if (ec) {
        std::cerr << "Unable to read root certificates file: " << tls_root_certs_filename;
        return {};
    }

    return tls_options;
}

std::shared_ptr<grpc::ServerCredentials> MakeSslServerCredentials(const std::string &tls_private_key_filename,
                                                                  const std::string &tls_cert_chain_filename,
                                                                  const std::string &tls_root_certs_filename,
                                                                  std::error_code &ec) {
    grpc::SslCredentialsOptions tls_creds =
            ReadTlsCredentials(tls_private_key_filename, tls_cert_chain_filename, tls_root_certs_filename, ec);
    if (ec) return {};

    grpc::SslServerCredentialsOptions tls_server_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
    grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp{std::move(tls_creds.pem_private_key),
                                                           std::move(tls_creds.pem_cert_chain)};
    tls_server_opts.pem_key_cert_pairs.push_back(std::move(pkcp));
    tls_server_opts.pem_root_certs = std::move(tls_creds.pem_root_certs);

    std::shared_ptr<grpc::ServerCredentials> credentials = grpc::SslServerCredentials(tls_server_opts);
    if (!credentials) {
        ec = make_error_code(ProtoheadErrorCode::kProtoheadTlsFailure);
        std::cerr << "Unable to create tls server credentials."
                  << " Private key file: " << tls_private_key_filename
                  << " Certificate chain file: " << tls_cert_chain_filename
                  << " Root certs file: " << tls_root_certs_filename;
        return {};
    }

    return credentials;
}

class ServerImpl final {
 public:
  ~ServerImpl() {
    server_->Shutdown();
    // Always shutdown the completion queue after the server.
    cq_->Shutdown();
  }

  // There is no shutdown handling in this code.
  void Run() {
    std::string server_address("0.0.0.0:50051");

    ServerBuilder builder;
    // Listen on the given address without any authentication mechanism.
      // Listen on the given address without any authentication mechanism.
      std::string privateKeyFileName = "/home/lucas/workspace/Northguard/tls/server/server.key.p8";
      std::string certChainFileName = "/home/lucas/workspace/Northguard/tls/server/server.cert.pem";
      std::string rootCertsFileName = "/home/lucas/workspace/Northguard/tls/intermediate/certs/ca-chain-bundle.cert.pem";

      std::error_code ec;
      std::shared_ptr<grpc::ServerCredentials> credentials = MakeSslServerCredentials(
              privateKeyFileName, certChainFileName, rootCertsFileName, ec);

      builder.AddListeningPort(server_address, credentials);
    // Register "service_" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *asynchronous* service.
    builder.RegisterService(&service_);
    // Get hold of the completion queue used for the asynchronous communication
    // with the gRPC runtime.
    cq_ = builder.AddCompletionQueue();
    // Finally assemble the server.
    server_ = builder.BuildAndStart();
    std::cout << "Server listening on " << server_address << std::endl;

    // Proceed to the server's main loop.
    HandleRpcs();
  }

 private:
  // Class encompasing the state and logic needed to serve a request.
  class CallData {
   public:
    // Take in the "service" instance (in this case representing an asynchronous
    // server) and the completion queue "cq" used for asynchronous communication
    // with the gRPC runtime.
    CallData(Greeter::AsyncService* service, ServerCompletionQueue* cq)
        : service_(service), cq_(cq), responder_(&ctx_), status_(CREATE) {
      // Invoke the serving logic right away.
      Proceed();
    }

    void Proceed() {
      if (status_ == CREATE) {
        // Make this instance progress to the PROCESS state.
        status_ = PROCESS;

        // As part of the initial CREATE state, we *request* that the system
        // start processing SayHello requests. In this request, "this" acts are
        // the tag uniquely identifying the request (so that different CallData
        // instances can serve different requests concurrently), in this case
        // the memory address of this CallData instance.
        service_->RequestSayHello(&ctx_, &request_, &responder_, cq_, cq_,
                                  this);
      } else if (status_ == PROCESS) {
        // Spawn a new CallData instance to serve new clients while we process
        // the one for this CallData. The instance will deallocate itself as
        // part of its FINISH state.

          auto auth_context = ctx_.auth_context();
          for (auto it = auth_context->begin(); it != auth_context->end(); it++) {
              std::cout << "property:" << (*it).first << "," << (*it).second << "\n";
          }

        new CallData(service_, cq_);

        // The actual processing.
        std::string prefix("Hello ");
        reply_.set_message(prefix + request_.name());

        // And we are done! Let the gRPC runtime know we've finished, using the
        // memory address of this instance as the uniquely identifying tag for
        // the event.
        status_ = FINISH;
        responder_.Finish(reply_, Status::OK, this);
      } else {
        GPR_ASSERT(status_ == FINISH);
        // Once in the FINISH state, deallocate ourselves (CallData).
        delete this;
      }
    }

   private:
    // The means of communication with the gRPC runtime for an asynchronous
    // server.
    Greeter::AsyncService* service_;
    // The producer-consumer queue where for asynchronous server notifications.
    ServerCompletionQueue* cq_;
    // Context for the rpc, allowing to tweak aspects of it such as the use
    // of compression, authentication, as well as to send metadata back to the
    // client.
    ServerContext ctx_;

    // What we get from the client.
    HelloRequest request_;
    // What we send back to the client.
    HelloReply reply_;

    // The means to get back to the client.
    ServerAsyncResponseWriter<HelloReply> responder_;

    // Let's implement a tiny state machine with the following states.
    enum CallStatus { CREATE, PROCESS, FINISH };
    CallStatus status_;  // The current serving state.
  };

  // This can be run in multiple threads if needed.
  void HandleRpcs() {
    // Spawn a new CallData instance to serve new clients.
    new CallData(&service_, cq_.get());
    void* tag;  // uniquely identifies a request.
    bool ok;
    while (true) {
      // Block waiting to read the next event from the completion queue. The
      // event is uniquely identified by its tag, which in this case is the
      // memory address of a CallData instance.
      // The return value of Next should always be checked. This return value
      // tells us whether there is any kind of event or cq_ is shutting down.
      GPR_ASSERT(cq_->Next(&tag, &ok));
      GPR_ASSERT(ok);
      static_cast<CallData*>(tag)->Proceed();
    }
  }

  std::unique_ptr<ServerCompletionQueue> cq_;
  Greeter::AsyncService service_;
  std::unique_ptr<Server> server_;
};

int main(int argc, char** argv) {
  ServerImpl server;
  server.Run();

  return 0;
}
