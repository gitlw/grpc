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
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
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
//------ end of impls

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
  Status SayHello(ServerContext* context, const HelloRequest* request,
                  HelloReply* reply) override {
      auto auth_context = context->auth_context();
      for (auto it = auth_context->begin(); it != auth_context->end(); it++) {
          std::cout << "property:" << (*it).first << "," << (*it).second << "\n";
      }
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }
};

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

void RunServer() {
  std::string server_address("0.0.0.0:50051");
  GreeterServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  std::string privateKeyFileName = "/home/lucas/workspace/Northguard/tls/server/server.key.p8";
  std::string certChainFileName = "/home/lucas/workspace/Northguard/tls/server/server.cert.pem";
  std::string rootCertsFileName = "/home/lucas/workspace/Northguard/tls/intermediate/certs/ca-chain-bundle.cert.pem";

  std::error_code ec;
  std::shared_ptr<grpc::ServerCredentials> credentials = MakeSslServerCredentials(
          privateKeyFileName, certChainFileName, rootCertsFileName, ec);

  builder.AddListeningPort(server_address, credentials);
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  RunServer();

  return 0;
}
