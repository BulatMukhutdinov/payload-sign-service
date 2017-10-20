package jp.co.soramitsu;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import io.grpc.*;
import io.grpc.stub.StreamObserver;
import iroha.protocol.BlockOuterClass;
import iroha.protocol.CommandServiceGrpc;
import iroha.protocol.Commands;
import iroha.protocol.Primitive;
import jp.co.soramitsu.payloadsignservice.CreateAccountRequest;
import jp.co.soramitsu.payloadsignservice.PayloadSignServiceGrpc;
import jp.co.soramitsu.util.Strings;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import static jp.co.soramitsu.util.LambdaExceptionUtil.rethrowConsumer;

public class PayloadSignServer {
    private static final Logger logger = Logger.getLogger(PayloadSignServer.class.getName());

    private final ManagedChannel channel;
    private final CommandServiceGrpc.CommandServiceBlockingStub blockingStub;
    private final int port;

    private Optional<Server> server;

    /**
     * Create a RouteGuide server listening on {@code port}
     */
    private PayloadSignServer(String irohaHost, int irohaPort, int port) {
        this.port = port;
        channel = ManagedChannelBuilder.forAddress(irohaHost, irohaPort)
                // Channels are secure by default (via SSL/TLS). Disable TLS to avoid needing certificates.
                .usePlaintext(true)
                .build();
        blockingStub = CommandServiceGrpc.newBlockingStub(channel);
    }

    /**
     * Start serving requests.
     */
    private void start() throws IOException {
        logger.log(Level.INFO, () -> "Server started, listening on port " + port);
        server = Optional.of(ServerBuilder.forPort(port)
                .addService(new PayloadSignService())
                .build()
                .start());

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.log(Level.WARNING, () -> "*** shutting down gRPC server since JVM is shutting down");
            PayloadSignServer.this.stop();
            logger.log(Level.WARNING, () -> "*** server shut down");
        }));
    }

    /**
     * Stop serving requests and shutdown resources.
     */
    private void stop() {
        server.ifPresent(Server::shutdown);
    }

    /**
     * Await termination on the main thread since the grpc library uses daemon threads.
     */
    private void blockUntilShutdown() throws InterruptedException {
        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
        server.ifPresent(rethrowConsumer(Server::awaitTermination));
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        final PayloadSignServer server = new PayloadSignServer("localhost", 50051, 50051);
        server.start();
        server.blockUntilShutdown();
    }

    private class PayloadSignService extends PayloadSignServiceGrpc.PayloadSignServiceImplBase {

        @Override
        public void createAccount(CreateAccountRequest request, StreamObserver<Empty> responseObserver) {
            logger.log(Level.INFO, () -> "new createAccount request is received");
            logger.log(Level.INFO, () -> "accountName = '" + request.getAccountName()
                    + "' domainId = '" + request.getDomainId() + "'");
            // Get and validate account name
            String accountName = request.getAccountName();
            if (!Pattern.matches(Strings.REGEX_ACCOUNT_NAME, accountName)) {
                logger.log(Level.WARNING, () -> "accountName is invalid. Aborting the request...");
                responseObserver.onError(Status.INVALID_ARGUMENT
                        .withDescription(String.format(Strings.ERROR_INVALID_ARGUMENT, "accountName", Strings.REGEX_ACCOUNT_NAME))
                        .asRuntimeException());
            }

            // Get and validate domain id
            String domainId = request.getDomainId();
            if (!Pattern.matches(Strings.REGEX_DOMAIN_ID, accountName)) {
                logger.log(Level.WARNING, () -> "domainId is invalid. Aborting the request...");
                responseObserver.onError(Status.INVALID_ARGUMENT
                        .withDescription(String.format(Strings.ERROR_INVALID_ARGUMENT, "domainId", Strings.REGEX_DOMAIN_ID))
                        .asRuntimeException());
            }

            Optional<StatusRuntimeException> exception = createAccount(accountName, domainId, request.getMainPubkey());
            if (exception.isPresent()) {
                logger.log(Level.SEVERE, () -> "Exception occurred during account creation");
                logger.log(Level.SEVERE, () -> exception.get().getLocalizedMessage());
                responseObserver.onError(exception.get());
            } else {
                logger.log(Level.INFO, () -> "Request has been successfully processed");
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        }

        private Optional<StatusRuntimeException> createAccount(String accountName, String domainId, ByteString publicKey) {
            try {
                BlockOuterClass.Transaction transaction = BlockOuterClass.Transaction
                        .newBuilder()
                        .setPayload(buildPayload(accountName, domainId, publicKey))
                        .addAllSignature(buildSignature())
                        .build();
                blockingStub.torii(transaction);
                return Optional.empty();
            } catch (Exception e) {
                return Optional.of(Status.INTERNAL.withDescription(e.getLocalizedMessage()).asRuntimeException());
            }
        }

        private BlockOuterClass.Transaction.Payload buildPayload(String accountName, String domainId, ByteString publicKey) {
            return BlockOuterClass.Transaction.Payload
                    .newBuilder()
                    .addAllCommands(buildCommand(accountName, domainId, publicKey))
                    .setCreatorAccountId("") // todo implement
                    .setTxCounter(0)
                    .setCreatedTime(System.currentTimeMillis() / 1000)
                    .build();
        }

        private List<Primitive.Signature> buildSignature() {
            return Collections.emptyList(); // todo implement
        }

        private List<Commands.Command> buildCommand(String accountName, String domainId, ByteString publicKey) {
            Commands.CreateAccount createAccount = Commands.CreateAccount
                    .newBuilder()
                    .setAccountName(accountName)
                    .setDomainId(domainId)
                    .setMainPubkey(publicKey)
                    .build();
            return Collections.singletonList(Commands.Command.newBuilder().setCreateAccount(createAccount).build());
        }
    }
}