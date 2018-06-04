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
    private static final byte INST_CHARGING_REQUEST    = 'c';
    private static final byte INST_CHARGING_FINISH     = 'd';
    private static final byte INST_PUMPING_REQUEST     = 'o';
    private static final byte INST_PUMPING_AUTH        = 'q';
    private static final byte INST_PUMPING_FINISH      = 'r';

    private static final byte X = 0;
    private static final byte Y = 1;

    private static final short ID = (short) 42; //TODO: Deze moeten allemaal groter (shorts?) en specifieker
    private static final byte certificate = 99;

    private static final short RSA_TYPE = 1024;
    private static final short RSA_BLOCKSIZE = 128;

    private static RSAPrivateKey cardPrivateKey;
    private static RSAPublicKey cardPublicKey;
    private static KeyPair cardKeyPair;
    private static Cipher cardCipher;

    private RandomData rng;
    private byte[] cryptoBuffer;

    private byte[] extendedBuffer;
    private byte incomingApduStreamLength;
    private byte incomingApduStreamPointer;
    private byte incomingApduStreamResolve;
    private short outgoingStreamLength;

    private short[] xy;

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


        cryptoBuffer = new byte[RSA_BLOCKSIZE+RSA_BLOCKSIZE];
        //cryptoBuffer = JCSystem.makeTransientByteArray((short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE), JCSystem.CLEAR_ON_RESET);
        extendedBuffer = JCSystem.makeTransientByteArray((short) (RSA_BLOCKSIZE+RSA_BLOCKSIZE), JCSystem.CLEAR_ON_RESET);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        try{
          cardKeyPair = new KeyPair(KeyPair.ALG_RSA, RSA_TYPE);
          cardKeyPair.genKeyPair();
          cardPrivateKey = (RSAPrivateKey) cardKeyPair.getPrivate();
          cardPublicKey = (RSAPublicKey) cardKeyPair.getPublic();

          cardCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        } catch (CryptoException e) {
          short reason = e.getReason();
          ISOException.throwIt(reason);
        }


        m = 0;
        A = (short) 0;
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
                buffer[0] = 7;
                buffer[1] = 8;
                buffer[2] = 9;
                buffer[3] = 8;
                buffer[4] = 7;
                buffer[5] = 3;
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
        case INST_CHARGING_REQUEST: //Charging protocol actie 1, Protocol Request
            handleChargingProtocolRequest(buffer);
            break;
        case INST_CHARGING_FINISH: //Charging protocol actie 5, Signature and session numbers
            finishChargingProtocol(buffer);
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

    public short encrypt_double(short length, PublicKey key, byte[] buffer, short offset){
      short l = encrypt((short) 100, key, buffer, (short) 0, offset);
      return (short) (l + encrypt((short) (length-(short) 100), key, buffer, (short) 100, (short) (offset + RSA_BLOCKSIZE)));
    }

    public short encrypt(short length, PublicKey key, byte[] buffer, short cryptoffset, short offset){
      cardCipher.init(key, Cipher.MODE_ENCRYPT);
      return cardCipher.doFinal(cryptoBuffer, cryptoffset, length, buffer, offset);
    }

    public void decrypt_double(short length, short offset){
      decrypt(RSA_BLOCKSIZE, offset);
      decrypt((short) (length - RSA_BLOCKSIZE), (short) (offset + (short) 100));
    }

    public void decrypt(short length, short offset){
      cardCipher.init(cardPrivateKey, Cipher.MODE_DECRYPT);
      cardCipher.doFinal(cryptoBuffer, offset, length, cryptoBuffer, offset);
    }

    public void sign(short length, byte[] buffer){
      cardCipher.init(cardPrivateKey, Cipher.MODE_ENCRYPT);
      cardCipher.doFinal(cryptoBuffer, (short) 0, length, cryptoBuffer, (short) 0);
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

        buffer[4] = 123;
        short lel = serializeKey(cardPublicKey, buffer, (short) 5);

        messageLength = (short)((short) lel+ (short) 5);
    }

    ///Charging Protocol

    void handleChargingProtocolRequest(byte[] buffer){

        //Handle input: Terminal -> Card: Protocol request, N1
        short N1 = bufferToShort(buffer, (short) 5);

        cryptoBuffer[0] = buffer[5];
        cryptoBuffer[1] = buffer[6];

        //Handle output: Card -> Terminal: Card auth response\nN2, A, sign(ID..A..N1..N2, sk(C))
        rng.generateData(buffer, (short) 5, (short) 2);
        short N2 = bufferToShort(buffer, (short) 5);
        //Byte A

        cryptoBuffer[2] = buffer[5];
        cryptoBuffer[3] = buffer[6];

        byte[] x_b = shortToByteArray(A);
        cryptoBuffer[4] = x_b[0];
        cryptoBuffer[5] = x_b[1];

        x_b = shortToByteArray(ID);
        cryptoBuffer[6] = x_b[0];
        cryptoBuffer[7] = x_b[1];

        sign((short) 8, buffer);

        buffer[7] = cryptoBuffer[0];
        buffer[8] = cryptoBuffer[1];
        buffer[9] = cryptoBuffer[2];
        buffer[10] = cryptoBuffer[3];
        buffer[11] = cryptoBuffer[4];
        buffer[12] = cryptoBuffer[5];
        buffer[13] = cryptoBuffer[6];
        buffer[14] = cryptoBuffer[7];

        messageLength = (short) 15;
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

        //Handle input: Terminal -> Card: Protocol request, N1
        byte N1 = buffer[5];

        //Handle output: Card -> Terminal: Pump auth request\n ID, N1, N2, pk(c), C(c)
        //Byte N1
        byte N2 = (byte) 81; //TODO: deze moet nog random gegenereerd worden
        //Byte publicKey //TODO: moet een int worden
        //Byte certificate //TODO: moet een int worden

        //Write output
        buffer[5] = ID;
        buffer[6] = N1;
        buffer[7] = N2;
        //buffer[8] = publicKey;
        buffer[9] = certificate;

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
