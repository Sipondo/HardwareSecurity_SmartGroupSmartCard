package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Sample Java Card Calculator applet which operates on signed shorts. Overflow
 * is silent.
 *
 * The instructions are the ASCII characters of the keypad keys: '0' - '9', '+',
 * '-', * 'x', ':', '=', etc. This means that the terminal should send an APDU
 * for each key pressed.
 *
 * Response APDU consists of 5 data bytes. First byte indicates whether the M
 * register contains a non-zero value. The third and fourth bytes encode the X
 * register (the signed short value to be displayed).
 *
 * The only non-transient field is m. This means that m is stored in EEPROM and
 * all other memory used is RAM.
 *
 * @author Martijn Oostdijk (martijno@cs.kun.nl)
 * @author Wojciech Mostowski (woj@cs.ru.nl)
 *
 */
public class CalcApplet extends Applet implements ISO7816 {

private static final byte INST_INIT                = 'b';
private static final byte INST_INIT_FINISH         = 'a';
private static final byte INST_CHARGING_REQUEST    = 'c';
private static final byte INST_CHARGING_REALFIN    = 'z';
private static final byte INST_PUMPING_REALSTART   = '1';
private static final byte INST_PUMP_FINISH         = '2';

private static final short RSA_TYPE = 1024;
private static final short RSA_BLOCKSIZE = 128;

private static RSAPrivateKey cardPrivateKey;
private static RSAPublicKey cardPublicKey;

private static RSAPublicKey globalPublicKey;
private static RSAPublicKey termPublicKey;

private static KeyPair cardKeyPair;
private static Cipher cardCipher;
private static Signature cardSignature;

private RandomData rng;
private byte[] cryptoBuffer;
private byte[] cardKeyCertificate;

private short extendedBufferLength;
private byte[] extendedBuffer;
private byte incomingApduStreamLength;
private byte incomingApduStreamPointer;
private byte incomingApduStreamResolve;
private short outgoingStreamLength;

private short cardId;
private short N1;
private short N2;
private short m;
private short messageLength;
private short A;

/**
 * Construct the applet. This constructor is only called once (card installation).
 */
public CalcApplet() {
        incomingApduStreamLength = 0;
        incomingApduStreamPointer = 99;
        incomingApduStreamResolve = 0;
        extendedBufferLength = 0;
        m = 0;
        A = (short) 0;

        //cryptoBuffer = new byte[RSA_BLOCKSIZE+RSA_BLOCKSIZE];
        cryptoBuffer = JCSystem.makeTransientByteArray((short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE), JCSystem.CLEAR_ON_RESET);
        extendedBuffer = JCSystem.makeTransientByteArray((short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE), JCSystem.CLEAR_ON_RESET);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        cryptoConstructor();

        register();
}

/**
 * Generate a public and a private key on card installation.
 */
public void cryptoConstructor(){
        try{
                cardKeyPair = new KeyPair(KeyPair.ALG_RSA, RSA_TYPE);
                cardKeyPair.genKeyPair();
                cardPrivateKey = (RSAPrivateKey) cardKeyPair.getPrivate();
                cardPublicKey = (RSAPublicKey) cardKeyPair.getPublic();

                cardCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
                cardSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        } catch (CryptoException e) {
                short reason = e.getReason();
                ISOException.throwIt(reason);
        }
}

/**
 * Call the class constructor on card installation.
 * @param  buffer          Passed down, ignored
 * @param  offset          Passed down, ignored
 * @param  length          Passed down, ignored
 * @throws SystemException Installation exception
 */
public static void install(byte[] buffer, short offset, byte length)
throws SystemException {
        new CalcApplet();
}

/**
 * Returns selectable. As no variables have to be changed on select this call
 * will simply return the boolean value true.
 * @return true
 */
public boolean select() {
        return true;
}

/**
 * This function resolves collecting the master's extendedBuffer.
 * This is initiated by an APDU stream request sent from the master.
 * The function is called within the process function. It
 * is checked before the actual header is checked as incoming APDU
 * stream blocks do not contain a header.
 * @param  apdu          Incoming APDU object
 * @param  buffer        Buffer module of the APDU object
 * @throws ISOException  Inappropriate length exception
 * @throws APDUException Invalid APDU exception
 */
public void resolveIncomingAPDUStream(APDU apdu, byte[] buffer) throws ISOException, APDUException {
        byte[] b;
        byte[] plain;

        short input_length = bufferToShort(buffer, (short) 2);
        Util.arrayCopy(buffer, (short) 5, extendedBuffer, (short)((short) incomingApduStreamPointer*(short) RSA_BLOCKSIZE), input_length);
        incomingApduStreamPointer = (byte) (incomingApduStreamPointer + (byte) 1);

        if (incomingApduStreamPointer<incomingApduStreamLength) {
                buffer[0] = 0;
                buffer[1] = 0;
                buffer[2] = incomingApduStreamPointer;
                buffer[3] = incomingApduStreamLength;
                buffer[4] = 0;
                buffer[5] = 0;
                messageLength = (short) 6;
        }else{

                switch (incomingApduStreamResolve) {
                case INST_INIT_FINISH:
                        cardKeyCertificate = new byte[extendedBufferLength];
                        Util.arrayCopy(extendedBuffer, (short) 0, cardKeyCertificate, (short) 0, extendedBufferLength);

                        buffer[0] = 0;
                        buffer[1] = 0;
                        buffer[2] = 0;
                        buffer[3] = 0;
                        buffer[4] = 11;
                        buffer[5] = 0;


                        messageLength = (short) 6;
                        break;
                case INST_CHARGING_REALFIN:
                        Util.arrayCopy(extendedBuffer, (short) 0, cryptoBuffer, (short) 0, (short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE));
                        decrypt_double(cardPrivateKey, (short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE), (short) 0);

                        plain = new byte[6];
                        plain[0] = cryptoBuffer[0];
                        plain[1] = cryptoBuffer[1];

                        b = shortToByteArray(N1);
                        plain[2] = b[0];
                        plain[3] = b[1];

                        b = shortToByteArray(N2);
                        plain[4] = b[0];
                        plain[5] = b[1];

                        if(verify(globalPublicKey, plain, (short) 6, (short) 0, cryptoBuffer,RSA_BLOCKSIZE, (short) 2)) {
                                buffer[4] = 8;
                                A = bufferToShort(cryptoBuffer, (short) 0);
                        }else{
                                buffer[4] = 7;
                        }

                        buffer[0] = 0;
                        buffer[1] = 0;
                        buffer[2] = 0;
                        buffer[3] = 0;
                        buffer[5] = 0;
                        messageLength = (short) 6;
                        break;
                case INST_PUMPING_REALSTART:
                        buffer[0] = 0;
                        buffer[1] = 0;
                        buffer[2] = 0;
                        buffer[3] = 0;
                        buffer[4] = 17;
                        buffer[5] = 0;

                        messageLength = (short) 6;

                        short keyl = (short)((short)(outgoingStreamLength - (short) 2) - RSA_BLOCKSIZE);
                        if (verify(globalPublicKey, extendedBuffer, keyl, (short) 2, extendedBuffer, RSA_BLOCKSIZE, (short)(keyl + (short) 2))) {
                                buffer[4] = 18;

                                termPublicKey = deserializeKey(extendedBuffer, (short) 2);

                                N1 = bufferToShort(extendedBuffer, (short) 0);

                                rng.generateData(extendedBuffer, (short) 0, (short) 2);
                                N2 = bufferToShort(extendedBuffer, (short) 0);

                                outgoingStreamLength = (short) 6;

                                b = shortToByteArray(A);
                                extendedBuffer[0] = b[0];
                                extendedBuffer[1] = b[1];

                                b = shortToByteArray(N1);
                                extendedBuffer[2] = b[0];
                                extendedBuffer[3] = b[1];

                                b = shortToByteArray(N2);
                                extendedBuffer[4] = b[0];
                                extendedBuffer[5] = b[1];

                                serializeKey(cardPublicKey, extendedBuffer, outgoingStreamLength);
                                outgoingStreamLength = (short) (outgoingStreamLength + (short) 135);
                                Util.arrayCopy(cardKeyCertificate, (short) 0, extendedBuffer, outgoingStreamLength, RSA_BLOCKSIZE);
                                outgoingStreamLength = (short) 269;
                                Util.arrayCopy(extendedBuffer, (short) 0, cryptoBuffer, (short) 0, outgoingStreamLength);
                                outgoingStreamLength = (short)(sign(outgoingStreamLength, extendedBuffer, (short) 0, outgoingStreamLength) + outgoingStreamLength);

                                outgoingStreamLength = (short)(outgoingStreamLength+RSA_BLOCKSIZE);
                                b = shortToByteArray((short)(outgoingStreamLength/RSA_BLOCKSIZE));
                                buffer[5] = b[1];

                                b = shortToByteArray(outgoingStreamLength);
                                buffer[6] = b[0];
                                buffer[7] = b[1];

                                A = (short) 0;

                                messageLength = (short) 8;


                        }
                        break;
                case INST_PUMP_FINISH:
                        buffer[0] = 0;
                        buffer[1] = 0;
                        buffer[2] = 0;
                        buffer[3] = 0;
                        buffer[5] = 0;

                        plain = new byte[6];
                        plain[0] = extendedBuffer[0];
                        plain[1] = extendedBuffer[1];

                        b = shortToByteArray(N1);
                        plain[2] = b[0];
                        plain[3] = b[1];

                        b = shortToByteArray(N2);
                        plain[4] = b[0];
                        plain[5] = b[1];

                        if(verify(termPublicKey, plain, (short) 6, (short) 0, extendedBuffer,RSA_BLOCKSIZE, (short) 2)) {
                                buffer[4] = 69;
                                A = bufferToShort(extendedBuffer, (short) 0);
                        }else{
                                buffer[4] = 68;
                        }

                        messageLength = (short) 6;
                        break;
                default:
                        break;
                }
        }
}

/**
 * This is the main handler for incoming APDU objects.
 * The master sends a command APDU which is processed in this function.
 * This function calls the subfunctions resolveIncomingAPDUStream first.
 * Unlike it's sister function in the terminal, this function does not split
 * into extra subfunctions for resolving outgoing APDU streams and
 * other instructions. This is because the java card code is more compact
 * than the code on the terminal side.
 * @param  apdu          Incoming command APDU object
 * @throws ISOException  Inappropriate length exception
 * @throws APDUException Invalid APDU exception
 */
public void process(APDU apdu) throws ISOException, APDUException {
        short numBytes = apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];
        short le = -1;
        messageLength = (short) 0;

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) {
                return;
        }

        if (incomingApduStreamPointer<incomingApduStreamLength) {
                resolveIncomingAPDUStream(apdu, buffer);
        }else{

                /**
                 * This is the card's version of resolveOutgoingAPDUStream
                 * As the size of the code is very limited we opted not to
                 * split it into a seperate function.
                 */
                byte outgoingStreamIndex = buffer[2];
                byte outgoingStreamEnd = buffer[3];

                if (outgoingStreamIndex < outgoingStreamEnd) { //if still handling an apduStream
                        apdu.setOutgoing();

                        short l = (short) (outgoingStreamLength - (short)(outgoingStreamIndex * RSA_BLOCKSIZE));
                        if (l>RSA_BLOCKSIZE) {
                                l = RSA_BLOCKSIZE;
                        }

                        apdu.setOutgoingLength(l);
                        apdu.sendBytesLong(extendedBuffer, (short) ((short) outgoingStreamIndex * RSA_BLOCKSIZE), l);
                        return;
                }

                /**
                 * This is the card's version of resolveRespondAPDU.
                 */

                switch (ins) {

                case INST_INIT:
                        handleInitialize(buffer);
                        break;
                case INST_INIT_FINISH:
                        finalizeInitialize(buffer);
                        break;

                case INST_CHARGING_REQUEST:
                        handleChargingProtocolRequest(buffer);
                        break;
                case INST_CHARGING_REALFIN:
                        realFinishUpCharging(buffer);
                        break;

                case INST_PUMPING_REALSTART:
                        reallyStartPumpingProtocol(buffer);
                        break;
                case INST_PUMP_FINISH:
                        reallyEndPumping(buffer);
                        break;

                default:
                        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                }
        }

        le = apdu.setOutgoing();
        if (le < 5) {
                ISOException.throwIt((short) (SW_WRONG_LENGTH | 5));
        }

        apdu.setOutgoingLength(messageLength);
        apdu.sendBytes((short) 0, messageLength);
}

/**
 * Translates a short to a byte array. Usually utilized for sending
 * integers to the slave.
 * @param  s Integer to be translated
 * @return   Byte[] representation of the integer
 */
public byte[] shortToByteArray(short s){
        byte[] b = new byte[2];
        b[0] = (byte)((s >> 8) & 0xff);
        b[1] = (byte)(s & 0xff);
        return b;
}

/**
 * Translates a byte array into a short. Usually utilized for receiving
 * integers from the slave.
 * @param  buffer Buffer that contains the integer in byte representation
 * @param  offset Offset in previously mentioned buffer
 * @return        Integer found at the offset in the buffer
 */
public short bufferToShort(byte[] buffer, short offset){
        return (short)( ((buffer[offset] & 0xff)<<8) | (buffer[(short)(offset+1)] & 0xff) );
}

/**
 * Extension to the encrypt function that can process two blocks instead of one.
 * This function has not been scaled up to contain a for-loop.
 * We have abstained from using constructs like for-loop on the javacard for
 * performance reasons. No protocol or transaction in our design document
 * requires encrypt or decrypt operations on more than two blocks.
 * The plaintext is always sourced from the cryptoBuffer.
 * @param  length    Length of the message
 * @param  key       Key to encrypt with
 * @param  buffer    Byte array that is written to
 * @param  offset    Offset of the destination in the buffer
 * @return           Encrypted text length
 */
public short encrypt_double(short length, Key key, byte[] buffer, short offset){
        short l = encrypt((short) 100, key, buffer, (short) 0, offset);
        return (short) (l + encrypt((short) (length-(short) 100), key, buffer, (short) 100, (short) (offset + RSA_BLOCKSIZE)));
}

/**
 * Encrypts plaintext
 * The plaintext is always sourced from the cryptoBuffer.
 * @param  length      Length of the message
 * @param  key         Key to encrypt with
 * @param  buffer      Byte array that is written to
 * @param  cryptoffset Offset of the source in the cryptoBuffer
 * @param  offset      Offset of the destination in the buffer
 * @return             Encrypted text length
 */
public short encrypt(short length, Key key, byte[] buffer, short cryptoffset, short offset){
        cardCipher.init(key, Cipher.MODE_ENCRYPT);
        return cardCipher.doFinal(cryptoBuffer, cryptoffset, length, buffer, offset);
}

/**
 * Extension to the decrypt function that can process two blocks instead of one.
 * This function has not been scaled up to contain a for-loop.
 * We have abstained from using constructs like for-loop on the javacard for
 * performance reasons. No protocol or transaction in our design document
 * requires encrypt or decrypt operations on more than two blocks.
 * The encrypted text must be in the cryptoBuffer. This function always
 * outputs into the cryptoBuffer for safety reasons.
 * @param  key    Key used for decryption
 * @param  length Length of the message
 * @param  offset Offset in the cryptoBuffer
 * @return        Decrypted text length
 */
public short decrypt_double(Key key, short length, short offset){
        short a = decrypt(key, RSA_BLOCKSIZE, offset);
        short b = decrypt(key, RSA_BLOCKSIZE, (short) (offset + RSA_BLOCKSIZE));
        Util.arrayCopy(cryptoBuffer, RSA_BLOCKSIZE, cryptoBuffer, a, b);
        return (short) (a+b);
}

/**
 * Decrypts a byte array into plaintext.
 * The encrypted text must be in the cryptoBuffer. This function always
 * outputs into the cryptoBuffer for safety reasons.
 * @param  key    Key used for decryption
 * @param  length Length of the message
 * @param  offset Offset in the cryptoBuffer
 * @return        Decrypted text length
 */
public short decrypt(Key key, short length, short offset){
        cardCipher.init(key, Cipher.MODE_DECRYPT);
        return cardCipher.doFinal(cryptoBuffer, offset, length, cryptoBuffer, offset);
}

/**
 * Signs given plaintext with the card private key.
 * The plaintext is always sourced from the cryptoBuffer.
 * @param  length      Length of the plaintext
 * @param  buffer      Buffer to write the signature in
 * @param  cryptoffset Offset of the plaintext in the cryptobuffer
 * @param  offset      Required offset for the encrypted text
 * @return             Length of the signature
 */
public short sign(short length, byte[] buffer, short cryptoffset, short offset){
        cardSignature.init(cardPrivateKey, Signature.MODE_SIGN);
        return cardSignature.sign(cryptoBuffer, cryptoffset, length, buffer, offset);
}

/**
 * Verify given plaintext against given encrypted text.
 * This is the only crypto operation that does not require the plaintext to be
 * in the cryptoBuffer. Verification is usually done on information sent from
 * the terminal. This means that it is more efficient pointing this operation
 * to the (extended)Buffer and that there are no security risks in doing so.
 * @param  key     Key used for decryption
 * @param  pSource Buffer containing the plaintext
 * @param  pLength Length of the plaintext
 * @param  pOffset Offset of the plaintext
 * @param  eSource Buffer containing the encrypted text
 * @param  eLength Length of the encrypted text
 * @param  eOffset Offset of the encrypted text
 * @return         Whether the text match (true) or not
 */
public boolean verify(RSAPublicKey key, byte[] pSource, short pLength, short pOffset, byte[] eSource, short eLength, short eOffset){
        //cardSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        cardSignature.init(key, Signature.MODE_VERIFY);
        return cardSignature.verify(pSource, pOffset, pLength, eSource, eOffset, eLength);
}

/**
 * Translates a key into a byte array under the following map:
 * [2] [expLen] [2] [modLen]
 * with the following contents, listed per block from left to right:
 *  - Length of the exponent in bytes
 *  - Value of the exponent in bytes
 *  - Length of the modulus in bytes
 *  - Value of the exponent in bytes
 * @param  key    Input public key
 * @param  buffer Buffer to write the byte array to
 * @param  offset Offset in said buffer
 * @return        Length of the byte array
 */
private final short serializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        short expLen = key.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        short modLen = key.getModulus(buffer, (short)(expLen + (short) (offset + 4)));
        Util.setShort(buffer, (short) (offset + (short) ((short) 2 + expLen)), RSA_BLOCKSIZE);
        return (short) (4 + expLen + RSA_BLOCKSIZE);
}

/**
 * Translate a byte array into a public key. Closely accompanies the
 * serializeKey function as it uses the same format:
 * [2] [expLen] [2] [modLen]
 * with the following contents, listed per block from left to right:
 *  - Length of the exponent in bytes
 *  - Value of the exponent in bytes
 *  - Length of the modulus in bytes
 *  - Value of the exponent in bytes
 * @param  buffer Buffer to source the key from
 * @param  offset Offset in said buffer
 * @return        Deserialized public key
 */
private final RSAPublicKey deserializeKey(byte[] buffer, short offset) {
        RSAPublicKey key = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, RSA_TYPE, false);
        short expLen = bufferToShort(buffer, offset);
        short modplace = (short) (offset + (short)((short) 4 + expLen));

        key.setExponent(buffer, (short) (offset + (short) 2), expLen);
        key.setModulus(buffer, modplace, RSA_BLOCKSIZE);

        return key;
}

/**
 * Receiver for the first message of the init protocol
 * @param buffer APDU data buffer
 */
void handleInitialize(byte[] buffer){

        globalPublicKey = deserializeKey(buffer, (short) 5);
        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = 0;
        buffer[3] = 0;
        buffer[4] = 10;
        short l = serializeKey(cardPublicKey, buffer, (short) 5);

        messageLength = (short)((short) 5 + l);
}

/**
 * Receiver for the final message of the init protocol
 * @param buffer APDU data buffer
 */
void finalizeInitialize(byte[] buffer){

        incomingApduStreamResolve = buffer[1];
        incomingApduStreamPointer = 0;
        incomingApduStreamLength = buffer[2];
        cardId = bufferToShort(buffer, (short) 5);
        extendedBufferLength = bufferToShort(buffer, (short) 9);


        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = incomingApduStreamPointer;
        buffer[3] = incomingApduStreamLength;
        buffer[4] = 0;

        messageLength = (short) 6;
}

/**
 * Receiver for the first message of the charging protocol
 * @param buffer APDU data buffer
 */
void handleChargingProtocolRequest(byte[] buffer){

        N1 = bufferToShort(buffer, (short) 5);

        cryptoBuffer[0] = buffer[5];
        cryptoBuffer[1] = buffer[6];

        rng.generateData(buffer, (short) 5, (short) 2);
        N2 = bufferToShort(buffer, (short) 5);

        cryptoBuffer[2] = buffer[5];
        cryptoBuffer[3] = buffer[6];

        byte[] x_b = shortToByteArray(cardId);
        cryptoBuffer[4] = x_b[0];
        cryptoBuffer[5] = x_b[1];

        x_b = shortToByteArray(A);
        cryptoBuffer[6] = x_b[0];
        cryptoBuffer[7] = x_b[1];

        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = 0;
        buffer[3] = 0;

        buffer[4] = 30;

        buffer[7] = x_b[0];
        buffer[8] = x_b[1];

        messageLength = (short)((short) 9 + sign((short) 8, buffer, (short) 0, (short) 9));
}

/**
 * Receiver for the final message of the charging protocol
 * @param buffer APDU data buffer
 */
void realFinishUpCharging(byte[] buffer){
        incomingApduStreamResolve = buffer[1];
        incomingApduStreamPointer = 0;
        incomingApduStreamLength = buffer[2];
        outgoingStreamLength = bufferToShort(buffer, (short) 5);


        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = incomingApduStreamPointer;
        buffer[3] = incomingApduStreamLength;
        buffer[4] = 0;
        buffer[5] = 0;

        messageLength = (short) 6;
}

/**
 * Receiver for the first message of the pumping protocol
 * @param buffer APDU data buffer
 */
void reallyStartPumpingProtocol(byte[] buffer){

        incomingApduStreamResolve = buffer[1];
        incomingApduStreamPointer = 0;
        incomingApduStreamLength = buffer[2];
        outgoingStreamLength = bufferToShort(buffer, (short) 5);


        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = incomingApduStreamPointer;
        buffer[3] = incomingApduStreamLength;
        buffer[4] = 0;
        buffer[5] = 0;

        messageLength = (short) 6;
}

/**
 * Receiver for the final message of the pumping protocol
 * @param buffer APDU data buffer
 */
void reallyEndPumping(byte[] buffer){

        incomingApduStreamResolve = buffer[1];
        incomingApduStreamPointer = 0;
        incomingApduStreamLength = buffer[2];

        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = incomingApduStreamPointer;
        buffer[3] = incomingApduStreamLength;
        buffer[4] = 0;
        buffer[5] = 0;

        messageLength = (short) 6;
}
}
