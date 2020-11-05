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

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <fstream>

#include <grpcpp/grpcpp.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;


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

    std::cout << "Reading private key file: " << tls_private_key_filename;
    tls_options.pem_private_key = ReadFile(tls_private_key_filename, ec);
    if (ec) {
        std::cerr << "Unable to read private key file: " << tls_private_key_filename;
        return {};
    }
    std::cout << "Reading certificate chain file: " << tls_cert_chain_filename;
    tls_options.pem_cert_chain = ReadFile(tls_cert_chain_filename, ec);
    if (ec) {
        std::cerr << "Unable to read certificate chain file: " << tls_cert_chain_filename;
        return {};
    }
    std::cout << "Reading root ca certs file: " << tls_root_certs_filename;
    tls_options.pem_root_certs = ReadFile(tls_root_certs_filename, ec);
    if (ec) {
        std::cerr << "Unable to read root certificates file: " << tls_root_certs_filename;
        return {};
    }

    return tls_options;
}

std::shared_ptr<grpc::ChannelCredentials> MakeSslChannelCredentials(const std::string &tls_private_key_filename,
                                                                  const std::string &tls_cert_chain_filename,
                                                                  const std::string &tls_root_certs_filename,
                                                                  std::error_code &ec) {
    grpc::SslCredentialsOptions tls_creds =
            ReadTlsCredentials(tls_private_key_filename, tls_cert_chain_filename, tls_root_certs_filename, ec);
    if (ec) return {};

    grpc::SslCredentialsOptions tls_client_opts;
    tls_client_opts.pem_root_certs = tls_creds.pem_root_certs;
    tls_client_opts.pem_cert_chain = tls_creds.pem_cert_chain;
    tls_client_opts.pem_private_key = tls_creds.pem_private_key;

    auto channel_creds = grpc::SslCredentials(tls_client_opts);
    if (!channel_creds) {
        ec = make_error_code(ProtoheadErrorCode::kProtoheadTlsFailure);
        std::cerr << "Unable to create tls channel credentials."
                  << " Private key file: " << tls_private_key_filename
                  << " Certificate chain file: " << tls_cert_chain_filename
                  << " Root certs file: " << tls_root_certs_filename;
        return {};
    }

    return channel_creds;
}

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

int main(int argc, char** argv) {
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint specified by
  // the argument "--target=" which is the only expected argument.
  // We indicate that the channel isn't authenticated (use of
  // InsecureChannelCredentials()).
  std::string target_str;
  std::string arg_str("--target");
  if (argc > 1) {
    std::string arg_val = argv[1];
    size_t start_pos = arg_val.find(arg_str);
    if (start_pos != std::string::npos) {
      start_pos += arg_str.size();
      if (arg_val[start_pos] == '=') {
        target_str = arg_val.substr(start_pos + 1);
      } else {
        std::cout << "The only correct argument syntax is --target=" << std::endl;
        return 0;
      }
    } else {
      std::cout << "The only acceptable argument is --target=" << std::endl;
      return 0;
    }
  } else {
    target_str = "ld0:50051";
  }

// Create a default SSL ChannelCredentials object.
    std::string privateKeyFileName = "/home/lucas/workspace/Northguard/tls/client/client.key.p8";
    std::string certChainFileName = "/home/lucas/workspace/Northguard/tls/client/client.cert.pem";
    std::string rootCertsFileName = "/home/lucas/workspace/Northguard/tls/intermediate/certs/ca-chain-bundle.cert.pem";

    std::error_code ec;
    auto channel_creds = MakeSslChannelCredentials(
            privateKeyFileName, certChainFileName, rootCertsFileName, ec);

  GreeterClient greeter(grpc::CreateChannel(target_str, channel_creds));
  std::string user("world");
  std::string reply = greeter.SayHello(user);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}
