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
    private static final byte INST_CHARGING_FINISH     = 'd';
    private static final byte INST_PUMPING_REQUEST     = 'o';
    private static final byte INST_PUMPING_AUTH        = 'q';
    private static final byte INST_PUMPING_FINISH      = 'r';
    private static final byte INST_PUMPING_REALSTART   = '1';
    private static final byte INST_PUMP_FINISH         = '2';

    private static final byte X = 0;
    private static final byte Y = 1;

    private static final short ID = (short) 42; //TODO: Deze moeten allemaal groter (shorts?) en specifieker
    private static final byte certificate = 99;

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
    private short[] xy;

    private short N1;
    private short N2;

    private short m;

    private byte[] lastOp;

    private boolean[] lastKeyWasDigit;

    private short messageLength;

    private short A;

    public CalcApplet() {
        xy = JCSystem.makeTransientShortArray((short) 2,
                JCSystem.CLEAR_ON_RESET);
        lastOp = JCSystem.makeTransientByteArray((short) 1,
                JCSystem.CLEAR_ON_RESET);
        lastKeyWasDigit = JCSystem.makeTransientBooleanArray((short) 1,
                JCSystem.CLEAR_ON_RESET);

        incomingApduStreamLength = 0;
        incomingApduStreamPointer = 99;
        incomingApduStreamResolve = 0;
        extendedBufferLength = 0;


        //cryptoBuffer = new byte[RSA_BLOCKSIZE+RSA_BLOCKSIZE];
        cryptoBuffer = JCSystem.makeTransientByteArray((short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE), JCSystem.CLEAR_ON_RESET);
        extendedBuffer = JCSystem.makeTransientByteArray((short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE), JCSystem.CLEAR_ON_RESET);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

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


        m = 0;
        A = (short) 42;
        register();
    }

    public static void install(byte[] buffer, short offset, byte length)
            throws SystemException {
        new CalcApplet();
    }

    public boolean select() {
        xy[X] = 0;
        xy[Y] = 0;
        lastOp[0] = (byte) '=';
        lastKeyWasDigit[0] = false;
        return true;
    }

    public void process(APDU apdu) throws ISOException, APDUException {
        short numBytes = apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS]; //Dit is de instructie byte, byte 1.
        short le = -1;
        //byte input_length = buffer[4]; // byte 4 geeft het aantal bytes aan in de body
        messageLength = (short) 0;

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) {
            return;
        }

        if (incomingApduStreamPointer<incomingApduStreamLength){
          short input_length = bufferToShort(buffer, (short) 2);
          Util.arrayCopy(buffer, (short) 5, extendedBuffer, (short)((short) incomingApduStreamPointer*(short) RSA_BLOCKSIZE), input_length);
          incomingApduStreamPointer = (byte) (incomingApduStreamPointer + (byte) 1);

        if (incomingApduStreamPointer<incomingApduStreamLength){
            buffer[0] = 0;
            buffer[1] = 0;
            buffer[2] = incomingApduStreamPointer;
            buffer[3] = incomingApduStreamLength;
            buffer[4] = 0;
            buffer[5] = 0;
            messageLength = (short) 6;
          }else{

            if (incomingApduStreamResolve==INST_PUMPING_FINISH){
                buffer[0] = 0;
                buffer[1] = 0;
                buffer[2] = 0;
                buffer[3] = 0;
                buffer[4] = 101;
                byte[] b = shortToByteArray((short)(outgoingStreamLength/RSA_BLOCKSIZE));
                buffer[5] = b[1];
                messageLength = (short) 6;
            }
            if (incomingApduStreamResolve==INST_INIT_FINISH){
              cardKeyCertificate = new byte[extendedBufferLength];
              Util.arrayCopy(extendedBuffer, (short) 0, cardKeyCertificate, (short) 0, extendedBufferLength);
              //Util.arrayCopy(extendedBuffer, (short) 0, cryptoBuffer, (short) 0, extendedBufferLength);
              //decrypt_double(globalPublicKey, extendedBufferLength,(short) 0);
              buffer[0] = 0;
              buffer[1] = 0;
              buffer[2] = 0;
              buffer[3] = 0;
              buffer[4] = 11;
              buffer[5] = 0;
              //serializePrivateKey(cardPrivateKey, extendedBuffer, (short) 6);
              // buffer[12] = cryptoBuffer[0];
              // buffer[13] = cryptoBuffer[1];
              // buffer[14] = cryptoBuffer[2];
              // buffer[15] = cryptoBuffer[3];
              // buffer[16] = cryptoBuffer[4];
              // buffer[17] = cryptoBuffer[5];

              messageLength = (short) 6;
            }
            if (incomingApduStreamResolve==INST_CHARGING_REALFIN){
              Util.arrayCopy(extendedBuffer, (short) 0, cryptoBuffer, (short) 0, (short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE));
              decrypt_double(cardPrivateKey, (short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE), (short) 0);

              byte[] plain = new byte[6];
              plain[0] = cryptoBuffer[0];
              plain[1] = cryptoBuffer[1];

              byte[] b;
              b = shortToByteArray(N1);
              plain[2] = b[0];
              plain[3] = b[1];

              b = shortToByteArray(N2);
              plain[4] = b[0];
              plain[5] = b[1];

              if(verify(globalPublicKey, plain, (short) 6, (short) 0, cryptoBuffer,RSA_BLOCKSIZE, (short) 2)){
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
            }

            if (incomingApduStreamResolve==INST_PUMPING_REALSTART){
              buffer[0] = 0;
              buffer[1] = 0;
              buffer[2] = 0;
              buffer[3] = 0;
              buffer[4] = 17;
              buffer[5] = 0;

              messageLength = (short) 6;

              short keyl = (short)((short)(outgoingStreamLength - (short) 2) - RSA_BLOCKSIZE);
              if (verify(globalPublicKey, extendedBuffer, keyl, (short) 2, extendedBuffer, RSA_BLOCKSIZE, (short)(keyl + (short) 2))){
                buffer[4] = 18;

                termPublicKey = deserializeKey(extendedBuffer, (short) 2);

                N1 = bufferToShort(extendedBuffer, (short) 0);

                rng.generateData(extendedBuffer, (short) 0, (short) 2);
                N2 = bufferToShort(extendedBuffer, (short) 0);

                outgoingStreamLength = (short) 6;

                byte[] b;
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

                outgoingStreamLength = (short) 269;//(short) (outgoingStreamLength + RSA_BLOCKSIZE);

                Util.arrayCopy(extendedBuffer, (short) 0, cryptoBuffer, (short) 0, outgoingStreamLength);
                //byte[] buftest = new byte[]{1,1};
                //Util.arrayCopy(buftest, (short) 0, cryptoBuffer, (short) 0, (short) 1);
                //outgoingStreamLength = (short)(sign((short) 2, extendedBuffer, (short) 0, (short) 1) + outgoingStreamLength);
                outgoingStreamLength = (short)(sign(outgoingStreamLength, extendedBuffer, (short) 0, outgoingStreamLength) + outgoingStreamLength);

                outgoingStreamLength = (short)(outgoingStreamLength+RSA_BLOCKSIZE);
                b = shortToByteArray((short)(outgoingStreamLength/RSA_BLOCKSIZE));
                buffer[5] = b[1];

                b = shortToByteArray(outgoingStreamLength);
                buffer[6] = b[0];
                buffer[7] = b[1];
                messageLength = (short) 8;


              }
            }
            if (incomingApduStreamResolve==INST_PUMP_FINISH){
              buffer[0] = 0;
              buffer[1] = 0;
              buffer[2] = 0;
              buffer[3] = 0;
              buffer[5] = 0;

              byte[] plain = new byte[6];
              plain[0] = extendedBuffer[0];
              plain[1] = extendedBuffer[1];

              byte[] b;
              b = shortToByteArray(N1);
              plain[2] = b[0];
              plain[3] = b[1];

              b = shortToByteArray(N2);
              plain[4] = b[0];
              plain[5] = b[1];

              if(verify(termPublicKey, plain, (short) 6, (short) 0, extendedBuffer,RSA_BLOCKSIZE, (short) 2)){
                buffer[4] = 69;
                A = bufferToShort(extendedBuffer, (short) 0);
              }else{
                buffer[4] = 68;
              }

              messageLength = (short) 6;
            }

          }
        }else{


        byte outgoingStreamIndex = buffer[2];
        byte outgoingStreamEnd = buffer[3];

        if (outgoingStreamIndex < outgoingStreamEnd){ //if still handling an apduStream
          apdu.setOutgoing();

          short l = (short) (outgoingStreamLength - (short)(outgoingStreamIndex * RSA_BLOCKSIZE));
          if (l>RSA_BLOCKSIZE){
            l = RSA_BLOCKSIZE;
          }

          apdu.setOutgoingLength(l);
          apdu.sendBytesLong(extendedBuffer, (short) ((short) outgoingStreamIndex * RSA_BLOCKSIZE), l);
          return;
        }


        switch (ins) {

        case INST_INIT:
            handleInitialize(buffer);
            break;
        case INST_INIT_FINISH:
            finalizeInitialize(buffer);
            break;
        case INST_CHARGING_REQUEST: //Charging protocol actie 1, Protocol Request
            handleChargingProtocolRequest(buffer);
            break;
        case INST_CHARGING_FINISH: //Charging protocol actie 5, Signature and session numbers
            finishChargingProtocol(buffer);
            break;
        case INST_CHARGING_REALFIN:
            realFinishUpCharging(buffer);
            break;

        case INST_PUMPING_REQUEST: //Pumping protocol actie 1, Protocol Request
            handlePumpingProtocolRequest(buffer);
            break;
        case INST_PUMPING_AUTH: //Pumping protocol actie 3, Pump auth response, card auth request
            handlePumpingAuthResponse(buffer);
            break;
        case INST_PUMPING_FINISH: //Pumping protocol actie 5, Allowance update
            finishPumpingAllowanceUpdate(buffer);
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


        //Deze code zorgt dat het berichtje goed verstuurd wordt. Blijf af!
        //buffer[0] = (m == 0) ? (byte) 0x00 : (byte) 0x01;
        apdu.setOutgoingLength(messageLength);
        apdu.sendBytes((short) 0, messageLength);
    }

    public byte[] shortToByteArray(short s){
      byte[] b = new byte[2];
      b[0] = (byte)((s >> 8) & 0xff);
      b[1] = (byte)(s & 0xff);
      return b;
    }

    public short bufferToShort(byte[] buffer, short offset){
      return (short)( ((buffer[offset] & 0xff)<<8) | (buffer[(short)(offset+1)] & 0xff) );
    }

    public short encrypt_double(short length, Key key, byte[] buffer, short offset){
      short l = encrypt((short) 100, key, buffer, (short) 0, offset);
      return (short) (l + encrypt((short) (length-(short) 100), key, buffer, (short) 100, (short) (offset + RSA_BLOCKSIZE)));
    }

    public short encrypt(short length, Key key, byte[] buffer, short cryptoffset, short offset){
      cardCipher.init(key, Cipher.MODE_ENCRYPT);
      return cardCipher.doFinal(cryptoBuffer, cryptoffset, length, buffer, offset);
    }

    public short decrypt_double(Key key, short length, short offset){
      short a = decrypt(key, RSA_BLOCKSIZE, offset);
      short b = decrypt(key, RSA_BLOCKSIZE, (short) (offset + RSA_BLOCKSIZE));
      Util.arrayCopy(cryptoBuffer, RSA_BLOCKSIZE, cryptoBuffer, a, b);
      return (short) (a+b);
    }

    public short decrypt(Key key, short length, short offset){
      cardCipher.init(key, Cipher.MODE_DECRYPT);
      return cardCipher.doFinal(cryptoBuffer, offset, length, cryptoBuffer, offset);
    }

    public short sign(short length, byte[] buffer, short cryptoffset, short offset){
      cardSignature.init(cardPrivateKey, Signature.MODE_SIGN);
      return cardSignature.sign(cryptoBuffer, cryptoffset, length, buffer, offset);
    }

    public boolean verify(RSAPublicKey key, byte[] pSource, short pLength, short pOffset, byte[] eSource, short eLength, short eOffset){
      //cardSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
      cardSignature.init(key, Signature.MODE_VERIFY);
      return cardSignature.verify(pSource, pOffset, pLength, eSource, eOffset, eLength);
    }

    //reads the key object and stores it into the buffer
    private final short serializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        short expLen = key.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        short modLen = key.getModulus(buffer, (short)(expLen + (short) (offset + 4)));
        Util.setShort(buffer, (short) (offset + (short) ((short) 2 + expLen)), RSA_BLOCKSIZE);
        return (short) (4 + expLen + RSA_BLOCKSIZE);
    }

    //reads the key from the buffer and stores it inside the key object
    private final RSAPublicKey deserializeKey(byte[] buffer, short offset) {
        RSAPublicKey key = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, RSA_TYPE, false);
        short expLen = bufferToShort(buffer, offset);
        short modplace = (short) (offset + (short)((short) 4 + expLen));

        key.setExponent(buffer, (short) (offset + (short) 2), expLen);
        key.setModulus(buffer, modplace, RSA_BLOCKSIZE);

        return key;
    }

    //initialize

    void handleInitialize(byte[] buffer){

        //Stuur public key terug
        globalPublicKey = deserializeKey(buffer, (short) 5);
        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = 0;
        buffer[3] = 0;
        buffer[4] = 10;
        short l = serializeKey(cardPublicKey, buffer, (short) 5);

        messageLength = (short)((short) 5 + l);
    }

    void finalizeInitialize(byte[] buffer){

        //Stuur public key terug

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

    ///Charging Protocol

    void handleChargingProtocolRequest(byte[] buffer){

        //Handle input: Terminal -> Card: Protocol request, N1
        N1 = bufferToShort(buffer, (short) 5);

        cryptoBuffer[0] = buffer[5];
        cryptoBuffer[1] = buffer[6];

        //Handle output: Card -> Terminal: Card auth response\nN2, A, sign(ID..A..N1..N2, sk(C))
        rng.generateData(buffer, (short) 5, (short) 2);
        N2 = bufferToShort(buffer, (short) 5);
        //Byte A

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
        //N2 staat al op 5 en 6.
        buffer[7] = x_b[0];
        buffer[8] = x_b[1];

        messageLength = (short)((short) 9 + sign((short) 8, buffer, (short) 0, (short) 9));
        //messageLength = (short)((short) 9 + encrypt((short) 8, cardPrivateKey, buffer, (short) 0, (short) 9));
    }

    void finishChargingProtocol(byte[] buffer){

        //Handle input: Terminal -> Card: Signature and session numbers\nencrypt(A .. sign(A..N1..N2, sk(G), pk(C))
        //TODO: pak de encrypt uit


        // buffer[4] = 42;
        //
        // messageLength = (short) 5;
        buffer[4] = 92;
        RSAPublicKey globalPublicKey = deserializeKey(buffer, (short) 5);
        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = 0;
        buffer[3] = 0;

        cryptoBuffer[0] = 'h';
        cryptoBuffer[1] = 'e';
        cryptoBuffer[2] = 'l';
        cryptoBuffer[3] = 'p';
        cryptoBuffer[4] = ' ';
        cryptoBuffer[5] = 'm';
        cryptoBuffer[6] = 'i';
        cryptoBuffer[7] = 'j';
        cryptoBuffer[8] = ' ';
        cryptoBuffer[9] = 'u';
        cryptoBuffer[10] = 'i';
        cryptoBuffer[11] = 't';
        cryptoBuffer[12] = ' ';
        cryptoBuffer[13] = 'm';
        cryptoBuffer[14] = 'i';
        cryptoBuffer[15] = 'j';
        cryptoBuffer[16] = 'n';
        cryptoBuffer[17] = ' ';
        cryptoBuffer[18] = 'l';
        cryptoBuffer[19] = 'i';
        cryptoBuffer[20] = 'j';
        cryptoBuffer[21] = 'd';
        cryptoBuffer[22] = 'e';
        cryptoBuffer[23] = 'n';
        cryptoBuffer[24] = '!';
        messageLength = (short) ((short) 5 + encrypt((short) 25, globalPublicKey, buffer, (short) 0, (short) 5));

    }

    ///Pumping Protocol

    void handlePumpingProtocolRequest(byte[] buffer){

        // // //Handle input: Terminal -> Card: Protocol request, N1
        // // byte N1 = buffer[5];
        // //
        // // //Handle output: Card -> Terminal: Pump auth request\n ID, N1, N2, pk(c), C(c)
        // // //Byte N1
        // // byte N2 = (byte) 81; //TODO: deze moet nog random gegenereerd worden
        // // //Byte publicKey //TODO: moet een int worden
        // // //Byte certificate //TODO: moet een int worden
        //
        // //Write output
        // buffer[5] = ID;
        // buffer[6] = N1;
        // buffer[7] = N2;
        // //buffer[8] = publicKey;
        // buffer[9] = certificate;

        messageLength = (short) 10;
    }

    void handlePumpingAuthResponse(byte[] buffer){

      //Handle input: Terminal -> Card: Pump auth response, card auth request\nencrypt(N2..N1..pk(t)..C(t), pk(c))
      //TODO: decrypt en pak uit

      // byte publicKeyTerminal = buffer[7];
      // byte certificateTerminal = buffer[8];
      // byte receivedPublicKey = buffer[9];

      //TODO: Test of receivedPublicKey == publicKey

      //Handle output: Card -> Terminal: Card auth response\n encrypt(A..N1..N2, pk(t))
      //TODO: encrypt een output
      //handleInitialize(buffer);
      // buffer[5] = (byte) 221;
      buffer[0] = 0;
      buffer[1] = 0;
      buffer[2] = 0;
      buffer[3] = 0;
      buffer[4] = 100;
      RSAPublicKey globalPublicKey = deserializeKey(buffer, (short) 5);
      //buffer[11] = buffer[4];

      short crypto_l = serializeKey(globalPublicKey, cryptoBuffer, (short) 0);
      outgoingStreamLength = encrypt_double(crypto_l, globalPublicKey, extendedBuffer, (short) 0);
      byte[] b = shortToByteArray((short)(outgoingStreamLength/RSA_BLOCKSIZE));
      buffer[5] = b[1];
      messageLength = (short) 6;
      //messageLength = (short) ((short) 5 + encrypt((short) 110, globalPublicKey, extendedBuffer, (short) 5));
      //messageLength = (short) ((short) 5 + encrypt((short) 25, globalPublicKey, buffer, (short) 5));
      //messageLength = (short)((short) ((short) 0 + encrypt_double(crypto_l, globalPublicKey, extendedBuffer, (short) 0)) / (short) 2);
    }

    void finishPumpingAllowanceUpdate(byte[] buffer){

      //Handle input: Terminal -> Card: Allowance update\n encrypt(A..N1..N2, pk(c))
      //TODO: pak de encrypt uit


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

    void realFinishUpCharging(byte[] buffer){

      //Handle input: Terminal -> Card: Allowance update\n encrypt(A..N1..N2, pk(c))
      //TODO: pak de encrypt uit


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

    void reallyStartPumpingProtocol(byte[] buffer){

      //Handle input: Terminal -> Card: Allowance update\n encrypt(A..N1..N2, pk(c))
      //TODO: pak de encrypt uit


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

    void reallyEndPumping(byte[] buffer){

      //Handle input: Terminal -> Card: Allowance update\n encrypt(A..N1..N2, pk(c))
      //TODO: pak de encrypt uit


      incomingApduStreamResolve = buffer[1];
      incomingApduStreamPointer = 0;
      incomingApduStreamLength = buffer[2];
      //outgoingStreamLength = bufferToShort(buffer, (short) 5);


      buffer[0] = 0;
      buffer[1] = 0;
      buffer[2] = incomingApduStreamPointer;
      buffer[3] = incomingApduStreamLength;
      buffer[4] = 0;
      buffer[5] = 0;

      messageLength = (short) 6;
    }

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    /////////////////// HIER EINDIGT ONZE ORIGINAL CODE ///////////////////
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////

    void digit(byte d) {
        if (!lastKeyWasDigit[0]) {
            xy[Y] = xy[X];
            xy[X] = 0;
        }
        xy[X] = (short) ((short) (xy[X] * 10) + (short) (d & 0x00FF));
        lastKeyWasDigit[0] = true;
    }

    void operator(byte op) throws ISOException {
        switch (lastOp[0]) {
        case '+':
            xy[X] = (short) (xy[Y] + xy[X]);
            break;
        case '-':
            xy[X] = (short) (xy[Y] - xy[X]);
            break;
        case 'x':
            xy[X] = (short) (xy[Y] * xy[X]);
            break;
        case ':':
            if (xy[X] == 0) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            xy[X] = (short) (xy[Y] / xy[X]);
            break;
        default:
            break;
        }
        lastOp[0] = op;
        lastKeyWasDigit[0] = false;
    }

    void mem(byte op) {
        switch (op) {
        case 'S':
            m = xy[X];
            break;
        case 'R':
            xy[Y] = xy[X];
            xy[X] = m;
            break;
        case 'M':
            m += xy[X];
            break;
        }
        lastKeyWasDigit[0] = false;
    }
}
