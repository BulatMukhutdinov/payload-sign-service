package jp.co.soramitsu;

import com.google.protobuf.ByteString;
import io.grpc.*;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import iroha.protocol.*;
import jp.co.soramitsu.payloadsignservice.*;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import static jp.co.soramitsu.payloadsignservice.Status.*;
import static jp.co.soramitsu.util.Const.*;
import static jp.co.soramitsu.util.LambdaExceptionUtil.rethrowConsumer;

public class App {
    private static final Logger logger = Logger.getLogger(App.class.getName());

    private final ManagedChannel channel;
    private final CommandServiceGrpc.CommandServiceBlockingStub blockingStub;

    private Optional<Server> server;

    /**
     * Create a RouteGuide server listening on {@code port}
     */
    private App() {
        channel = ManagedChannelBuilder.forAddress(
                System.getProperty("iroha.address"),
                Integer.parseInt(System.getProperty("iroha.port")))
                // Channels are secure by default (via SSL/TLS). Disable TLS to avoid needing certificates.
                .usePlaintext(true)
                .build();
        blockingStub = CommandServiceGrpc.newBlockingStub(channel);
    }

    /**
     * Start serving requests.
     */
    private void start() throws IOException {
        logger.log(Level.INFO, () -> "Server started, listening on port " + System.getProperty("this.port"));
        server = Optional.of(ServerBuilder.forPort(Integer.parseInt(System.getProperty("this.port")))
                .addService(new PayloadSignService())
                .build()
                .start());

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.log(Level.WARNING, () -> "*** shutting down gRPC server since JVM is shutting down");
            App.this.stop();
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
    private void blockUntilShutdown() {
        server.ifPresent(rethrowConsumer(Server::awaitTermination));
    }

    public static void main(String[] args) throws IOException {
        FileInputStream propFile =
                new FileInputStream("props.txt");
        Properties p =
                new Properties(System.getProperties());
        p.load(propFile);
        System.setProperties(p);

        final App server = new App();
        server.start();
        server.blockUntilShutdown();
    }

    private class PayloadSignService extends PayloadSignServiceGrpc.PayloadSignServiceImplBase {


        @Override
        public void status(StatusRequest statusRequest, StreamObserver<StatusResponse> responseObserver) {
            logger.log(Level.INFO, () -> "status is requested by hash");
            try {
                Endpoint.TxStatusRequest request = Endpoint.TxStatusRequest.newBuilder()
                        .setTxHash(statusRequest.getHash())
                        .build();
                Endpoint.TxStatus txStatus = blockingStub.status(request).getTxStatus();
                jp.co.soramitsu.payloadsignservice.Status status;

                switch (txStatus) {
                    case STATELESS_VALIDATION_FAILED:
                        status = STATELESS_VALIDATION_FAILED;
                        break;
                    case STATELESS_VALIDATION_SUCCESS:
                        status = STATELESS_VALIDATION_SUCCESS;
                        break;
                    case STATEFUL_VALIDATION_FAILED:
                        status = STATEFUL_VALIDATION_FAILED;
                        break;
                    case STATEFUL_VALIDATION_SUCCESS:
                        status = STATEFUL_VALIDATION_SUCCESS;
                        break;
                    case COMMITTED:
                        status = COMMITTED;
                        break;
                    case ON_PROCESS:
                        status = ON_PROCESS;
                        break;
                    case NOT_RECEIVED:
                        status = NOT_RECEIVED;
                        break;
                    default:
                        status = UNRECOGNIZED;
                }

                logger.log(Level.INFO, () -> "Status request has been successfully processed");
                logger.log(Level.INFO, () -> "Status is " + status.name());
                responseObserver.onNext(StatusResponse.newBuilder().setStatus(status).build());
                responseObserver.onCompleted();
            } catch (StatusRuntimeException e) {
                logger.log(Level.SEVERE, () -> "Exception raised during status request");
                logger.log(Level.SEVERE, e::getLocalizedMessage);
                responseObserver.onError(e);
            }
        }

        @Override
        public void createAccount(CreateAccountRequest request, StreamObserver<CreateAccountResponse> responseObserver) {
            logger.log(Level.INFO, () -> "new createAccount request is received");
            logger.log(Level.INFO, () -> "accountName = '" + request.getAccountName()
                    + "' domainId = '" + request.getDomainId() + "'");
            // Get and validate account name
            String accountName = request.getAccountName();
            if (!Pattern.matches(REGEX_ACCOUNT_NAME, accountName)) {
                logger.log(Level.WARNING, () -> "accountName is invalid. Aborting the request...");
                responseObserver.onError(Status.INVALID_ARGUMENT
                        .withDescription(String.format(ERROR_INVALID_ARGUMENT, "accountName", REGEX_ACCOUNT_NAME))
                        .asRuntimeException());
            }

            // Get and validate domain id
            String domainId = request.getDomainId();
            if (!Pattern.matches(REGEX_DOMAIN_ID, accountName)) {
                logger.log(Level.WARNING, () -> "domainId is invalid. Aborting the request...");
                responseObserver.onError(Status.INVALID_ARGUMENT
                        .withDescription(String.format(ERROR_INVALID_ARGUMENT, "domainId", REGEX_DOMAIN_ID))
                        .asRuntimeException());
            }

            try {
                byte[] hash = createAccount(accountName, domainId, request.getMainPubkey());
                logger.log(Level.INFO, () -> "Create account request has been successfully processed");
                responseObserver.onNext(CreateAccountResponse.newBuilder().setHash(ByteString.copyFrom(hash)).build());
                responseObserver.onCompleted();
            } catch (StatusRuntimeException | NoSuchAlgorithmException | SignatureException | InvalidKeyException exception) {
                logger.log(Level.SEVERE, () -> "Exception raised during account creation");
                logger.log(Level.SEVERE, exception::getLocalizedMessage);
                responseObserver.onError(exception);
            }
        }

        private byte[] createAccount(String accountName, String domainId, ByteString publicKey)
                throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            BlockOuterClass.Transaction.Payload payload = buildPayload(accountName, domainId, publicKey);
            SignatureResult result = buildSignature(payload.toByteArray());

            BlockOuterClass.Transaction transaction = BlockOuterClass.Transaction
                    .newBuilder()
                    .setPayload(payload)
                    .addAllSignature(result.signature)
                    .build();
            blockingStub.torii(transaction);
            return result.hash;
        }

        private BlockOuterClass.Transaction.Payload buildPayload(String accountName, String domainId, ByteString publicKey) {
            return BlockOuterClass.Transaction.Payload
                    .newBuilder()
                    .addAllCommands(buildCommand(accountName, domainId, publicKey))
                    .setCreatorAccountId(System.getProperty("this.id"))
                    .setTxCounter(0)
                    .setCreatedTime(System.currentTimeMillis())
                    .build();
        }

        private SignatureResult buildSignature(byte[] payload) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            //Code sign here
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
            EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));

            EdDSAPrivateKeySpec privateKey = new EdDSAPrivateKeySpec(spec, hexStringToByteArray(System.getProperty("this.private_key")));

            PrivateKey sKey = new EdDSAPrivateKey(privateKey);
            sgr.initSign(sKey);

            //Create SHA3-256
            SHA3.DigestSHA3 sha3 = new SHA3.DigestSHA3(256);

            //Set payload to SHA3
            sha3.update(payload);

            //Sign SHA3
            byte[] msgToSign = sha3.digest();
            sgr.update(msgToSign);

            // Build Signature
            Primitive.Signature signature = Primitive.Signature
                    .newBuilder()
                    .setSignature(ByteString.copyFrom(sgr.sign()))
                    .setPubkey(ByteString.copyFrom(hexStringToByteArray(System.getProperty("this.public_key"))))
                    .build();

            return new SignatureResult(msgToSign, Collections.singletonList(signature));
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

        private byte[] hexStringToByteArray(String s) {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16));
            }
            return data;
        }

        private class SignatureResult {

            private byte[] hash;

            private List<Primitive.Signature> signature;

            SignatureResult(byte[] hash, List<Primitive.Signature> signature) {
                this.hash = hash;
                this.signature = signature;
            }
        }
    }
}