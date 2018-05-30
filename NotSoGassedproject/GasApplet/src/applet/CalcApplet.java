package applet;

import javacard.framework.*;
import javacard.security.*;

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

    private static final byte INST_CHARGING_REQUEST    = 'c';
    private static final byte INST_CHARGING_FINISH     = 'd';
    private static final byte INST_PUMPING_REQUEST     = 'o';
    private static final byte INST_PUMPING_AUTH        = 'q';
    private static final byte INST_PUMPING_FINISH      = 'r';

    private static final byte X = 0;
    private static final byte Y = 1;

    private static final byte ID = 42; //TODO: Deze moeten allemaal groter (shorts?) en specifieker
    private static final byte publicKey = 14;
    private static final byte certificate = 99;

    private RandomData rng;

    private short[] xy;

    private short m;

    private byte[] lastOp;

    private boolean[] lastKeyWasDigit;

    private short messageLength;

    private byte A; //TODO: maak een short

    public CalcApplet() {
        xy = JCSystem.makeTransientShortArray((short) 2,
                JCSystem.CLEAR_ON_RESET);
        lastOp = JCSystem.makeTransientByteArray((short) 1,
                JCSystem.CLEAR_ON_RESET);
        lastKeyWasDigit = JCSystem.makeTransientBooleanArray((short) 1,
                JCSystem.CLEAR_ON_RESET);

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        m = 0;
        A = (byte) 0;
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
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS]; //Dit is de instructie byte, byte 1.
        short le = -1;
        byte input_length = buffer[4]; // byte 4 geeft het aantal bytes aan in de body
        messageLength = (short) 0;

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) {
            return;
        }

        switch (ins) {

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
      b[0] = (byte)(s & 0xff);
      b[1] = (byte)((s >> 8) & 0xff);
      return b;
    }

    public short bufferToShort(byte[] buffer, short offset){
      return (short)( ((buffer[offset] & 0xff)<<8) | (buffer[(short)(offset+1)] & 0xff) );
    }

    ///Charging Protocol

    void handleChargingProtocolRequest(byte[] buffer){

        //Handle input: Terminal -> Card: Protocol request, N1
        short N1 = bufferToShort(buffer, (short) 5);

        //Handle output: Card -> Terminal: Card auth response\nN2, A, sign(ID..A..N1..N2, sk(C))
        rng.generateData(buffer, (short) 5, (short) 2);
        short N2 = bufferToShort(buffer, (short) 5);
        //Byte A
        byte sign = (byte) ((short) N1 + N2 + (short) A + (short) ID); //hier moet nog de secret key bij

        //Write output
        buffer[7] = A;
        buffer[8] = sign;

        messageLength = (short) 9;
    }

    void finishChargingProtocol(byte[] buffer){

        //Handle input: Terminal -> Card: Signature and session numbers\nencrypt(A .. sign(A..N1..N2, sk(G), pk(C))
        //TODO: pak de encrypt uit


        buffer[5] = 42;

        messageLength = (short) 6;
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
        buffer[8] = publicKey;
        buffer[9] = certificate;

        messageLength = (short) 10;
    }

    void handlePumpingAuthResponse(byte[] buffer){

      //Handle input: Terminal -> Card: Pump auth response, card auth request\nencrypt(N2..N1..pk(t)..C(t), pk(c))
      //TODO: decrypt en pak uit

      byte publicKeyTerminal = buffer[7];
      byte certificateTerminal = buffer[8];
      byte receivedPublicKey = buffer[9];

      //TODO: Test of receivedPublicKey == publicKey

      //Handle output: Card -> Terminal: Card auth response\n encrypt(A..N1..N2, pk(t))
      //TODO: encrypt een output

      buffer[5] = 42;

      messageLength = (short) 6;
    }

    void finishPumpingAllowanceUpdate(byte[] buffer){

      //Handle input: Terminal -> Card: Allowance update\n encrypt(A..N1..N2, pk(c))
      //TODO: pak de encrypt uit


      buffer[5] = 42;

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
