package jp.co.soramitsu;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import io.grpc.*;
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
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import static jp.co.soramitsu.payloadsignservice.StatusResponse.Status.*;
import static jp.co.soramitsu.util.Const.*;
import static jp.co.soramitsu.util.LambdaExceptionUtil.rethrowConsumer;

public class App {

    private static final Logger logger = Logger.getLogger(App.class.getName());

    private static AtomicLong counter = new AtomicLong();

    private final CommandServiceGrpc.CommandServiceBlockingStub commandServiceBlockingStub;

    private final QueryServiceGrpc.QueryServiceBlockingStub queryServiceBlockingStub;

    private Optional<Server> server;

    /**
     * Create a RouteGuide server listening on {@code port}
     */
    private App() {
        ManagedChannel channel = ManagedChannelBuilder.forAddress(
                System.getProperty("iroha.address"),
                Integer.parseInt(System.getProperty("iroha.port")))
                // Channels are secure by default (via SSL/TLS). Disable TLS to avoid needing certificates.
                .usePlaintext(true)
                .build();
        commandServiceBlockingStub = CommandServiceGrpc.newBlockingStub(channel);
        queryServiceBlockingStub = QueryServiceGrpc.newBlockingStub(channel);
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
        public void setAccountDetail(SetAccountDetailRequest request, StreamObserver<Empty> responseObserver) {
            logger.log(Level.INFO, () -> "setAccountDetail request is received");
            logger.log(Level.INFO, () -> "accountId = '" + request.getAccountId() + "'" +
                    "key = '" + request.getKey() + "'" +
                    "value = '" + request.getValue() + "'");
            try {
                BlockOuterClass.Transaction.Payload payload = buildTransactionPayload(buildSetAccountDetailCommand(
                        request.getAccountId(), request.getKey(), request.getValue()));
                SignatureResult result = buildSignature(payload.toByteArray());
                BlockOuterClass.Transaction transaction = BlockOuterClass.Transaction
                        .newBuilder()
                        .setPayload(payload)
                        .addSignature(result.signature)
                        .build();
                commandServiceBlockingStub.torii(transaction);
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
                logger.log(Level.INFO, () -> "Set account detail request has been successfully processed");
            } catch (StatusRuntimeException | NoSuchAlgorithmException | SignatureException | InvalidKeyException exception) {
                logger.log(Level.SEVERE, () -> "Exception raised during account setting request");
                onError(exception, responseObserver);
            }
        }

        private List<Commands.Command> buildSetAccountDetailCommand(String accountId, String key, String value) {
            Commands.SetAccountDetail setAccountDetail = Commands.SetAccountDetail
                    .newBuilder()
                    .setAccountId(accountId)
                    .setKey(key)
                    .setValue(value)
                    .build();
            return Collections.singletonList(Commands.Command.newBuilder().setSetAccountDetail(setAccountDetail).build());
        }

        @Override
        public void getAccount(GetAccountRequest request, StreamObserver<GetAccountResponse> responseObserver) {
            logger.log(Level.INFO, () -> "getAccount request is received");
            logger.log(Level.INFO, () -> "accountId = '" + request.getAccountId() + "'");
            try {
                Responses.QueryResponse queryResponse = queryServiceBlockingStub.find(buildQuery(request.getAccountId()));
                Responses.Account irohaAccount = queryResponse.getAccountResponse().getAccount();
                GetAccountResponse.Account account = GetAccountResponse.Account.newBuilder()
                        .setAccountId(irohaAccount.getAccountId())
                        .setDomainId(irohaAccount.getDomainId())
                        .setQuorum(irohaAccount.getQuorum())
                        .setJsonData(irohaAccount.getJsonData())
                        .build();
                responseObserver.onNext(GetAccountResponse.newBuilder().setAccount(account).build());
                responseObserver.onCompleted();
                logger.log(Level.INFO, () -> "Get account request has been successfully processed");
            } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | StatusRuntimeException exception) {
                logger.log(Level.SEVERE, () -> "Exception raised during get account request");
                onError(exception, responseObserver);
            }
        }

        private Queries.Query buildQuery(String accountId) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            Queries.Query.Payload payload = buildQueryPayload(accountId);
            SignatureResult signature = buildSignature(payload.toByteArray());
            return Queries.Query
                    .newBuilder()
                    .setPayload(payload)
                    .setSignature(signature.signature)
                    .build();
        }

        private Queries.Query.Payload buildQueryPayload(String accountId) {
            return Queries.Query.Payload
                    .newBuilder()
                    .setCreatedTime(System.currentTimeMillis())
                    .setCreatorAccountId(System.getProperty("this.id"))
                    .setGetAccount(Queries.GetAccount.newBuilder().setAccountId(accountId).build())
                    .setQueryCounter(counter.getAndIncrement())
                    .build();
        }

        @Override
        public void status(StatusRequest statusRequest, StreamObserver<StatusResponse> responseObserver) {
            logger.log(Level.INFO, () -> "status request is received");
            logger.log(Level.INFO, () -> "hash = '" + statusRequest.getHash() + "'");

            Endpoint.TxStatusRequest request = Endpoint.TxStatusRequest.newBuilder()
                    .setTxHash(statusRequest.getHash())
                    .build();
            Endpoint.TxStatus txStatus = commandServiceBlockingStub.status(request).getTxStatus();
            jp.co.soramitsu.payloadsignservice.StatusResponse.Status status;
            try {
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

                responseObserver.onNext(StatusResponse.newBuilder().setStatus(status).build());
                responseObserver.onCompleted();
                logger.log(Level.INFO, () -> "Status request has been successfully processed");
                logger.log(Level.INFO, () -> "Status is " + status.name());
            } catch (StatusRuntimeException exception) {
                logger.log(Level.SEVERE, () -> "Exception raised during status request");
                onError(exception, responseObserver);
            }
        }

        @Override
        public void createAccount(CreateAccountRequest request, StreamObserver<CreateAccountResponse> responseObserver) {
            logger.log(Level.INFO, () -> "createAccount request is received");
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
                responseObserver.onNext(CreateAccountResponse.newBuilder().setHash(ByteString.copyFrom(hash)).build());
                responseObserver.onCompleted();
                logger.log(Level.INFO, () -> "Create account request has been successfully processed");
            } catch (StatusRuntimeException | NoSuchAlgorithmException | SignatureException | InvalidKeyException exception) {
                logger.log(Level.SEVERE, () -> "Exception raised during account creation");
                onError(exception, responseObserver);
            }
        }

        private byte[] createAccount(String accountName, String domainId, ByteString publicKey)
                throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            BlockOuterClass.Transaction.Payload payload = buildTransactionPayload(buildCreateAccountCommand(accountName, domainId, publicKey));
            SignatureResult result = buildSignature(payload.toByteArray());

            BlockOuterClass.Transaction transaction = BlockOuterClass.Transaction
                    .newBuilder()
                    .setPayload(payload)
                    .addSignature(result.signature)
                    .build();
            commandServiceBlockingStub.torii(transaction);
            return result.hash;
        }

        private BlockOuterClass.Transaction.Payload buildTransactionPayload(List<Commands.Command> commands) {
            return BlockOuterClass.Transaction.Payload
                    .newBuilder()
                    .addAllCommands(commands)
                    .setCreatorAccountId(System.getProperty("this.id"))
                    .setTxCounter(counter.getAndIncrement())
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

            return new SignatureResult(msgToSign, signature);
        }

        private List<Commands.Command> buildCreateAccountCommand(String accountName, String domainId, ByteString publicKey) {
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

            private Primitive.Signature signature;

            SignatureResult(byte[] hash, Primitive.Signature signature) {
                this.hash = hash;
                this.signature = signature;
            }
        }

        private void onError(Exception exception, StreamObserver responseObserver) {
            logger.log(Level.SEVERE, exception::getLocalizedMessage);
            responseObserver.onError(exception);
        }
    }
}