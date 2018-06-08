package terminal;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JOptionPane;

import java.security.SecureRandom;
import java.math.BigInteger;

import java.util.Random;
import java.util.Base64;
import java.util.Arrays;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;



//import javacard.security.RandomData;

public class CalcTerminal extends JPanel implements ActionListener {

static final String TITLE = "Terminal";
static final Font FONT = new Font("Monospaced", Font.BOLD, 24);
static final Dimension PREFERRED_SIZE = new Dimension(300, 300);

static final int DISPLAY_WIDTH = 20;
static JFrame frame;
static final String MSG_ERROR = "    -- error --     ";
static final String MSG_DISABLED = " -- insert card --  ";
static final String MSG_INVALID = " -- invalid card -- ";

private static final byte INST_INIT                = 'b';
private static final byte INST_INIT_FINISH         = 'a';
private static final byte INST_CHARGING_REQUEST    = 'c';
private static final byte INST_CHARGING_REALFIN    = 'z';
private static final byte INST_PUMPING_REALSTART   = '1';
private static final byte INST_PUMP_FINISH         = '2';

private static final String NAME_INIT = "Initialization Protocol";
private static final String NAME_CHAR = "Charging Protocol";
private static final String NAME_PUMP = "Pumping Protocol";


private static short CHARGE_TO_VALUE = 100;
private static final int RSA_TYPE = 1024;
private static final int RSA_BLOCKSIZE = 128;     //128 bij 1024

private Random rng;

private byte[] extendedBuffer;
private byte incomingApduStreamLength;
private byte incomingApduStreamPointer;
private byte incomingApduStreamResolve;
private short outgoingStreamLength;

RSAPrivateKey globalPrivateKey;
RSAPublicKey globalPublicKey;

RSAPrivateKey termPrivateKey;
RSAPublicKey termPublicKey;
byte[] termCertificate;

RSAPublicKey cardPublicKey;
short cardIDA;
short cardIDB;
Cipher termCipher;
Signature termSignature;

private short A;
private short N1;
private short N2;
private short cardId;

static final byte[] CALC_APPLET_AID = { (byte) 0x12, (byte) 0x34,
                                        (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xab };

static final CommandAPDU SELECT_APDU = new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, CALC_APPLET_AID);

JTextField display;
JPanel keypad;

CardChannel applet;

public CalcTerminal(JFrame parent) {
        Security.addProvider(new BouncyCastleProvider());
        rng = new Random();
        System.out.println("Live");

        extendedBuffer = new byte[RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE+RSA_BLOCKSIZE];
        incomingApduStreamLength = 0;
        incomingApduStreamPointer = 99;
        incomingApduStreamResolve = 0;

        Key privKey;
        try{
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
                SecureRandom random = new SecureRandom();
                generator.initialize(RSA_TYPE, random);

                KeyPair pair = generator.generateKeyPair();
                termCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
                termSignature = Signature.getInstance("SHA1withRSA", "BC");
                globalPublicKey = (RSAPublicKey) pair.getPublic();
                globalPrivateKey = (RSAPrivateKey) pair.getPrivate();

                //keys voor pumpterminal
                generator.initialize(RSA_TYPE, random);

                pair = generator.generateKeyPair();
                termPublicKey = (RSAPublicKey) pair.getPublic();
                termPrivateKey = (RSAPrivateKey) pair.getPrivate();

                termCertificate = sign(globalPrivateKey, serializeKey(termPublicKey));


        }catch(Exception e) {
                System.out.println("Failed to construct crypto!");
                System.out.println(e);
        }

        // end Crypto constructor

        buildGUI(parent);
        setEnabled(false);
        (new CardThread()).start();
}

void resolveIncomingAPDUStream(byte[] data) throws Exception {
        System.arraycopy(data, 0, extendedBuffer, (int) incomingApduStreamPointer*(int) RSA_BLOCKSIZE, data.length);
        incomingApduStreamPointer = (byte) (incomingApduStreamPointer + (byte) 1);

        if (incomingApduStreamPointer<incomingApduStreamLength) {
                CommandAPDU rapdu = new CommandAPDU(0,0,incomingApduStreamPointer,incomingApduStreamLength,0);
                readResponseAPDU(applet.transmit(rapdu));
        }else{
                switch(incomingApduStreamResolve) {
                case 100:
                        System.out.println("Resolved");
                        byte[] result = decrypt_double(extendedBuffer,globalPrivateKey,120,0); //TODO: length
                        System.out.println("decryptedBuffer: " + Base64.getEncoder().encodeToString(result));
                        break;
                case 101:
                        System.out.println("Resolved");
                        System.out.println(new String(extendedBuffer));
                        break;
                case 18:
                        System.out.println("Resolved");
                        short recA = bufferToShort(extendedBuffer,(short)0);
                        short recN1 = bufferToShort(extendedBuffer,(short)2);
                        short recN2 = bufferToShort(extendedBuffer,(short)4);

                        byte[] recpkC = Arrays.copyOfRange(extendedBuffer, 6, 141);
                        byte[] recCert = Arrays.copyOfRange(extendedBuffer, 141, 141+RSA_BLOCKSIZE);
                        byte[] recsign = Arrays.copyOfRange(extendedBuffer, 269, 269+RSA_BLOCKSIZE);

                        if (!(verify(globalPublicKey,recpkC,recCert))) {
                                return;
                        }
                        RSAPublicKey cardKey = deserializeKey(recpkC, (short) 0);

                        byte[] plain = Arrays.copyOfRange(extendedBuffer,0,269);
                        if (!(verify(cardKey,plain,recsign))) {
                                return;
                        }

                        //apdustream voor A, sign(a, N1, N2)
                        byte[] paUnsigned = new byte[6];
                        byte[] b;
                        A = recA;

                        boolean unsatisfied = true;
                        short newA = 0;
                        while (unsatisfied){
                          String amountQuery = JOptionPane.showInputDialog(frame,"Desired amount? Current allowance: " + A, null);
                          try{
                            newA = Short.parseShort(amountQuery);
                            if (newA < 0){
                              throw new Exception();
                            }
                            if (newA > A){
                              throw new Exception();
                            }
                            unsatisfied = false;
                          }catch(Exception e){}
                        }

                        A = newA;

                        b = shortToByteArray(A);
                        paUnsigned[0] = b[0];
                        paUnsigned[1] = b[1];
                        extendedBuffer[0] = b[0];
                        extendedBuffer[1] = b[1];

                        b = shortToByteArray(recN1);
                        paUnsigned[2] = b[0];
                        paUnsigned[3] = b[1];

                        b = shortToByteArray(recN2);
                        paUnsigned[4] = b[0];
                        paUnsigned[5] = b[1];
                        byte[] paSigned = sign(termPrivateKey, paUnsigned);

                        System.arraycopy(paSigned, 0, extendedBuffer, 2, paSigned.length);
                        outgoingStreamLength = (short) (paSigned.length + 2);

                        CommandAPDU rapdu = new CommandAPDU(0,INST_PUMP_FINISH,2,0,0);//(byte) (outgoingStreamLength/RSA_BLOCKSIZE));
                        System.out.println("Pump finalize");
                        readResponseAPDU(applet.transmit(rapdu));
                        break;
                default:
                        System.out.println("Unresolved stream end!");
                        //TODO throw exception
                        break;
                }
        }
}

void resolveOutgoingAPDUStream(byte[] data){
        byte outgoingStreamIndex = data[2];
        byte outgoingStreamEnd = data[3];
        short l = (short) (outgoingStreamLength - (short)(outgoingStreamIndex * RSA_BLOCKSIZE));
        if (l>RSA_BLOCKSIZE) {
                l = RSA_BLOCKSIZE;
        }

        byte[] l_b = shortToByteArray(l);

        short offset = (short) ((short) outgoingStreamIndex * RSA_BLOCKSIZE);
        byte[] message = Arrays.copyOfRange(extendedBuffer, offset, offset+l);
        CommandAPDU rapdu = new CommandAPDU(0,0,l_b[0],l_b[1],message);
        byte[] abytes = rapdu.getBytes();

        try{
                System.out.println("Sending stream object");
                readResponseAPDU(applet.transmit(rapdu));
        }catch(Exception e) {
                System.out.println(e);
        }
        return;
}

void resolveRespondAPDU(byte[] data){
        switch(data[4]) {
        case 10:  //Ontvang init 2
                try{
                        cardPublicKey = deserializeKey(data, (short) 5);

                        byte[] plainKey = Arrays.copyOfRange(data, 5, data.length);
                        byte[] encryptedKey = sign(globalPrivateKey, plainKey);
                        System.arraycopy(encryptedKey, 0, extendedBuffer, 0, encryptedKey.length);

                        byte[] id = new byte[6];
                        id[0] = 0;
                        id[1] = 1;
                        id[2] = 0;
                        id[3] = 0;

                        cardId = bufferToShort(id,(short)0);

                        byte[] elength = shortToByteArray((short)encryptedKey.length);
                        id[4] = elength[0];
                        id[5] = elength[1];

                        outgoingStreamLength = (short) encryptedKey.length;

                        CommandAPDU rapdu = new CommandAPDU(0,INST_INIT_FINISH,2,0,id);
                        System.out.println("Sent init finalize");
                        readResponseAPDU(applet.transmit(rapdu));

                }catch(Exception e) {
                        System.out.println("Failed to obtain card public key!");
                        System.out.println(e);
                }
                break;

        case 30: //Card auth response charging
                byte[] dat = Arrays.copyOfRange(data, 9, 137);
                byte[] plain = new byte[8];
                byte[] b;
                N2 = bufferToShort(data, (short) 5);

                A = CHARGE_TO_VALUE;
                b = shortToByteArray(N1);
                plain[0] = b[0];
                plain[1] = b[1];
                plain[2] = data[5]; //N2
                plain[3] = data[6];

                b = shortToByteArray(cardId);
                plain[4] = b[0];
                plain[5] = b[1];

                plain[6] = data[7];
                plain[7] = data[8];

                try{
                        if(verify(cardPublicKey,plain, dat)) {
                                System.out.println("Succes!");

                                byte[] newPlain = new byte[6];
                                b = shortToByteArray(A);
                                newPlain[0] = b[0];
                                newPlain[1] = b[1];

                                newPlain[2] = plain[0];
                                newPlain[3] = plain[1];
                                newPlain[4] = plain[2];
                                newPlain[5] = plain[3];

                                byte[] newSigned = sign(globalPrivateKey, newPlain);
                                byte[] plainTotal = new byte[newSigned.length+2];
                                plainTotal[0] = newPlain[0];
                                plainTotal[1] = newPlain[1];
                                byte[] sers = serializeKey(globalPublicKey);
                                System.arraycopy(newSigned, 0, plainTotal, 2, newSigned.length);
                                byte[] encryptedTotal = encrypt_double(plainTotal, cardPublicKey, 0, 0);
                                System.arraycopy(encryptedTotal, 0, extendedBuffer, 0, encryptedTotal.length);
                                outgoingStreamLength = (short) encryptedTotal.length;
                                CommandAPDU rapdu = new CommandAPDU(0, INST_CHARGING_REALFIN, 2, 0, shortToByteArray(outgoingStreamLength));
                                System.out.println("Finished building response apdu");
                                readResponseAPDU(applet.transmit(rapdu));
                                return;

                        }
                }catch(Exception e) {
                        System.out.println("Failed to verify signature!");
                        System.out.println(e);
                }
                break;

        case 18:
        case 100:
        case 101:
                try{
                        incomingApduStreamPointer = 0;
                        incomingApduStreamResolve = data[4];
                        incomingApduStreamLength = data[5];
                        CommandAPDU rapdu = new CommandAPDU(0,0,0,incomingApduStreamLength,0);
                        readResponseAPDU(applet.transmit(rapdu));
                } catch (CardException e) {
                        return;
                }
                break;
        case 11:
                System.out.println("Successfully completed initialization.");
                break;
        case 8:
                System.out.println("Successfully completed charging.");
                break;
        case 69:
                System.out.println("Successfully completed pumping.");
                break;
        default:
                System.out.println("Unrecognized APDU identifier");
                break;
        }
}


void readResponseAPDU(ResponseAPDU apdu) {
        byte[] data = apdu.getData();
        if (incomingApduStreamPointer<incomingApduStreamLength) {
                try{
                        resolveIncomingAPDUStream(data);
                } catch (Exception e) {
                        System.out.println("Critical error resolving APDUstream!");
                        System.out.println(e);
                }
                return;
        }

        int sw = apdu.getSW();
        if (sw != 0x9000 || data.length < 5) {
                setText(MSG_ERROR);
        } else {
                if (data[2] < data[3]) { //streamIndex < streamEnd
                        resolveOutgoingAPDUStream(data);
                        return;
                }

                System.out.println("\nInstruction number:");
                System.out.println(data[4]);

                resolveRespondAPDU(data);
        }
}

public ResponseAPDU startAPDUChain(byte ins) {
        CommandAPDU apdu;
        byte[] ser;
        switch(ins) {
        case INST_INIT:   //stuur de global key
                ser = serializeKey(globalPublicKey);
                apdu = new CommandAPDU(0, ins, 0, 0, ser);
                break;

        case INST_CHARGING_REQUEST:
                N1 = generateNonce();
                byte[] data = shortToByteArray(N1);
                apdu = new CommandAPDU(0, ins, 0, 0, data);
                break;

        case INST_PUMPING_REALSTART:
                byte[] tKeySer = serializeKey(termPublicKey);
                N1 = generateNonce();
                byte[] n_b = shortToByteArray(N1);
                extendedBuffer[0] = n_b[0];
                extendedBuffer[1] = n_b[1];
                System.arraycopy(tKeySer, 0, extendedBuffer, 2, tKeySer.length);
                System.arraycopy(termCertificate, 0, extendedBuffer, 2+tKeySer.length, termCertificate.length);
                outgoingStreamLength = (short)(2+tKeySer.length+termCertificate.length);
                apdu = new CommandAPDU(0, ins, 3, 0, shortToByteArray(outgoingStreamLength));
                break;
        default:
                apdu = new CommandAPDU(0, ins, 0, 0, 0);
                break;
        }

        try {
                byte[] data = apdu.getBytes();
                return applet.transmit(apdu);
        } catch (CardException e) {
                return null;
        }
}

void buildGUI(JFrame parent) {
        setLayout(new BorderLayout());
        display = new JTextField(DISPLAY_WIDTH);
        display.setHorizontalAlignment(JTextField.RIGHT);
        display.setEditable(false);
        display.setFont(FONT);
        display.setBackground(Color.darkGray);
        display.setForeground(Color.green);
        add(display, BorderLayout.NORTH);
        keypad = new JPanel(new GridLayout(3, 1));
        key(NAME_INIT);
        key(NAME_CHAR);
        key(NAME_PUMP);
        add(keypad, BorderLayout.CENTER);
        parent.addWindowListener(new CloseEventListener());
}

private byte[] bigIntFixer(BigInteger source){
        byte[] array = source.toByteArray();
        if (array[0] == 0) {
                byte[] tmp = new byte[array.length - 1];
                System.arraycopy(array, 1, tmp, 0, tmp.length);
                array = tmp;
        }
        return array;
}

//reads the key object and stores it into the buffer
private final byte[] serializeKey(RSAPublicKey key) {
        BigInteger exponent = key.getPublicExponent();
        BigInteger modulus = key.getModulus();

        byte[] exponentBytes = exponent.toByteArray();
        byte[] modulusBytes = bigIntFixer(modulus);

        short expLen = (short) exponentBytes.length;
        short modLen = (short) modulusBytes.length;

        byte[] buffer = new byte[expLen+modLen+4];
        byte[] b;

        b = shortToByteArray(expLen);
        buffer[0] = b[0];
        buffer[1] = b[1];

        System.arraycopy(exponentBytes, 0, buffer, 2, expLen);

        b = shortToByteArray(modLen);
        buffer[2+expLen] = b[0];
        buffer[3+expLen] = b[1];
        System.arraycopy(modulusBytes, 0, buffer, 4+expLen, modLen);

        return buffer;
}

//reads the key from the buffer and stores it inside the key object
private final RSAPublicKey deserializeKey(byte[] buffer, short offset) throws Exception {
        short expLen = bufferToShort(buffer, offset);
        short modLen = bufferToShort(buffer, (short) ((short) offset + (short)((short) 2 +expLen)));

        byte[] exponentBytes = Arrays.copyOfRange(buffer, offset+2, offset+2+expLen);
        byte[] modulusBytes = Arrays.copyOfRange(buffer, offset+4+expLen, offset+4+modLen+expLen);

        BigInteger exponent = new BigInteger(1, exponentBytes);
        BigInteger modulus = new BigInteger(1, modulusBytes);

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        Key generatePublic = kf.generatePublic(keySpec);

        RSAPublicKey testKey = (RSAPublicKey) generatePublic;

        return (RSAPublicKey) generatePublic;
}

void key(String txt) {
        if (txt == null) {
                keypad.add(new JLabel());
        } else {
                JButton button = new JButton(txt);
                button.addActionListener(this);
                keypad.add(button);
        }
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

public short generateNonce(){
        return (short) rng.nextInt(Short.MAX_VALUE+1);
}

byte[] decrypt_double(byte[] bArray, Key key, int length, int offset) throws Exception {
        byte[] a = decrypt(bArray, key, RSA_BLOCKSIZE, offset);
        byte[] b = decrypt(bArray, key, RSA_BLOCKSIZE, offset+RSA_BLOCKSIZE);
        byte[] output = new byte[a.length + b.length];

        System.arraycopy(a, 0, output, 0, a.length);
        System.arraycopy(b, 0, output, a.length, b.length);

        return output;
}

byte[] decrypt(byte[] bArray, Key key, int length, int offset) throws Exception {
        termCipher.init(Cipher.DECRYPT_MODE, key);

        byte[] mes = Arrays.copyOfRange(bArray, offset, 128+offset);
        return termCipher.doFinal(mes);
}

byte[] encrypt_double(byte[] data, Key key, int length, int offset) throws Exception {
        byte[] a = encrypt(data, key, 100, offset);
        byte[] b = encrypt(data, key, 100, offset+100);
        byte[] output = new byte[a.length + b.length];

        System.arraycopy(a, 0, output, 0, a.length);
        System.arraycopy(b, 0, output, a.length, b.length);

        return output;
}

byte[] encrypt(byte[] data, Key key, int length, int offset) throws Exception {
        termCipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] mes = Arrays.copyOfRange(data, offset, length+offset);
        return termCipher.doFinal(mes);
}

private byte[] sign(RSAPrivateKey key, byte[] plain) throws Exception {
        termSignature.initSign(key);
        termSignature.update(plain, 0, plain.length);
        return termSignature.sign();
}

private boolean verify(RSAPublicKey key, byte[] plain, byte[] encrypted) throws Exception {
        termSignature.initVerify(key);
        termSignature.update(plain);
        return termSignature.verify(encrypted, 0, encrypted.length);
}

void setMemory(boolean b) {
        String txt = getText();
        int l = txt.length();
        if (l < DISPLAY_WIDTH) {
                for (int i = 0; i < (DISPLAY_WIDTH - l); i++) {
                        txt = " " + txt;
                }
                txt = (b ? "M" : " ") + txt;
                setText(txt);
        }
}

public void setEnabled(boolean b) {
        super.setEnabled(b);
        if (b) {
                setText(0);
        } else {
                setText(MSG_DISABLED);
        }
        Component[] keys = keypad.getComponents();
        for (int i = 0; i < keys.length; i++) {
                keys[i].setEnabled(b);
        }
}

class CardThread extends Thread {
public void run() {
        try {
                TerminalFactory tf = TerminalFactory.getDefault();
                CardTerminals ct = tf.terminals();
                List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
                if (cs.isEmpty()) {
                        System.err.println("No terminals with a card found.");
                        return;
                }

                while (true) {
                        try {
                                for(CardTerminal c : cs) {
                                        if (c.isCardPresent()) {
                                          System.out.println("Found a card!");
                                                try {
                                                        Card card = c.connect("*");
                                                        try {
                                                                applet = card.getBasicChannel();
                                                                ResponseAPDU resp = applet.transmit(SELECT_APDU);
                                                                if (resp.getSW() != 0x9000) {
                                                                        throw new Exception("Select failed");
                                                                }
                                                                readResponseAPDU(startAPDUChain((byte) '='));
                                                                setEnabled(true);

                                                                // Wait for the card to be removed
                                                                while (c.isCardPresent());
                                                                setEnabled(false);
                                                                setText(MSG_DISABLED);
                                                                break;
                                                        } catch (Exception e) {
                                                                System.err.println("Card does not contain CalcApplet?!");
                                                                setText(MSG_INVALID);
                                                                sleep(2000);
                                                                setText(MSG_DISABLED);
                                                                continue;
                                                        }
                                                } catch (CardException e) {
                                                        System.err.println("Couldn't connect to card!");
                                                        setText(MSG_INVALID);
                                                        sleep(2000);
                                                        setText(MSG_DISABLED);
                                                        continue;
                                                }
                                        } else {
                                                System.err.println("No card present!");
                                                setText(MSG_INVALID);
                                                sleep(2000);
                                                setText(MSG_DISABLED);
                                                continue;
                                        }
                                }
                        } catch (CardException e) {
                                System.err.println("Card status problem!");
                        }
                }
        } catch (Exception e) {
                setEnabled(false);
                setText(MSG_ERROR);
                System.out.println("ERROR: " + e.getMessage());
                e.printStackTrace();
        }
}
}

public void actionPerformed(ActionEvent ae) {
        try {
                Object src = ae.getSource();
                if (src instanceof JButton) {
                        char c = 'x';
                        switch(((JButton) src).getText()) {
                        case NAME_INIT:
                                c = INST_INIT;
                                break;
                        case NAME_CHAR:
                                c = INST_CHARGING_REQUEST;
                                break;
                        case NAME_PUMP:
                                c = INST_PUMPING_REALSTART;
                                break;
                        default:
                                break;
                        }
                        readResponseAPDU(startAPDUChain((byte) c));
                }
        } catch (Exception e) {
                System.out.println(MSG_ERROR);
        }
}

String getText() {
        return display.getText();
}

void setText(String txt) {
        display.setText(txt);
}

void setText(int n) {
        setText(Integer.toString(n));
}

public Dimension getPreferredSize() {
        return PREFERRED_SIZE;
}

class CloseEventListener extends WindowAdapter {
public void windowClosing(WindowEvent we) {
        System.exit(0);
}
}

public static void main(String[] arg) {
        frame = new JFrame(TITLE);
        Container c = frame.getContentPane();
        CalcTerminal panel = new CalcTerminal(frame);
        c.add(panel);
        frame.setResizable(false);
        frame.pack();
        frame.setVisible(true);
}
}
