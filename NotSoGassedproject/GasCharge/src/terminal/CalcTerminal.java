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

    private static final long serialVersionUID = 1L;
    static final String TITLE = "Terminal";
    static final Font FONT = new Font("Monospaced", Font.BOLD, 24);
    static final Dimension PREFERRED_SIZE = new Dimension(300, 300);

    static final int DISPLAY_WIDTH = 20;
    static final String MSG_ERROR = "    -- error --     ";
    static final String MSG_DISABLED = " -- insert card --  ";
    static final String MSG_INVALID = " -- invalid card -- ";

    private static final byte INST_CHARGING_REQUEST    = 'c'; //Dit zijn de identifiers voor de communicatie. TODO: maak identifiers voor de communicatie terug.
    private static final byte INST_CHARGING_FINISH     = 'd';
    private static final byte INST_PUMPING_REQUEST     = 'o';
    private static final byte INST_PUMPING_AUTH        = 'q';
    private static final byte INST_PUMPING_FINISH      = 'r';

    private Random rng;

    RSAPrivateKey globalPrivateKey;
    RSAPublicKey globalPublicKey;

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
        // Provider providers[] = Security.getProviders();
        // System.out.println(providers.length);
        //

        Key privKey;
        try{
          KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
          SecureRandom random = new SecureRandom();
          generator.initialize(512, random);

          KeyPair pair = generator.generateKeyPair();
          globalPublicKey = (RSAPublicKey) pair.getPublic();
          globalPrivateKey = (RSAPrivateKey) pair.getPrivate();

          System.out.println("\npublic length:" + globalPublicKey.getEncoded().length);
          System.out.println("private length:" + globalPrivateKey.getEncoded().length);
          System.out.println("\npublickey : " + Base64.getEncoder().encodeToString(globalPublicKey.getEncoded()));
          System.out.println("privatekey : " + Base64.getEncoder().encodeToString(globalPrivateKey.getEncoded()));

          System.out.println("\n\npublic modulus: " + globalPublicKey.getModulus());
          System.out.println("public exponent: " + globalPublicKey.getPublicExponent());
          System.out.println("\nprivate modulus: " + globalPrivateKey.getModulus());
          System.out.println("private exponent: " + globalPrivateKey.getPrivateExponent());
          System.out.println("\n");

          byte[] ser = serializeKey(globalPublicKey);
          System.out.println("serialized key: " + Base64.getEncoder().encodeToString(ser));
          System.out.println("\npublickey : " + Base64.getEncoder().encodeToString(globalPublicKey.getEncoded()));
          System.out.println("public key (deser): " + Base64.getEncoder().encodeToString(deserializeKey(ser,(short)0).getEncoded()));



        // }catch(Exception e){
        //   System.out.println("Failed to construct keys!");
        //   System.out.println(e);
        // }
        //
        // //Encrypt-decrypt test
        //
        // try{
          Cipher cip = Cipher.getInstance("RSA");
          cip.init(Cipher.ENCRYPT_MODE, globalPublicKey);

          byte[] message = new byte[5];
          message[0] = 'h';
          message[1] = 'a';
          message[2] = 'l';
          message[3] = 'l';
          message[4] = 'o';

          byte[] output = cip.doFinal(message);//, 0, 5);

          Cipher decip = Cipher.getInstance("RSA");
          decip.init(Cipher.DECRYPT_MODE, globalPrivateKey);

          byte[] input = decip.doFinal(output);

          System.out.println("plain hallo : " + new String(message));
          System.out.println("encrypted hallo : " + new String(output));
          System.out.println("decrypted hallo : " + new String(input));
        }catch(Exception e){
          System.out.println("Failed to construct cipher!");
          System.out.println(e);
        }

        // end Crypto constructor

        buildGUI(parent);
        setEnabled(false);
        (new CardThread()).start();
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
        keypad = new JPanel(new GridLayout(3, 3));
        key("b");
        key("c");//(String) INST_CHARGING_REQUEST);
        key("d");//(String) INST_CHARGING_FINISH);
        key("o");//(String) INST_PUMPING_REQUEST);
        key("q");//(String) INST_PUMPING_AUTH);
        key("r");//(String) INST_PUMPING_FINISH);
        key("1");
        key("2");
        key("3");
        add(keypad, BorderLayout.CENTER);
        parent.addWindowListener(new CloseEventListener());
    }

    //reads the key object and stores it into the buffer
    private final byte[] serializeKey(RSAPublicKey key) {
        BigInteger exponent = key.getPublicExponent();
        BigInteger modulus = key.getModulus();

        byte[] exponentBytes = exponent.toByteArray();
        byte[] modulusBytes = modulus.toByteArray();

        short expLen = (short) exponentBytes.length;
        System.out.println("\n\nHey hallo!");
        System.out.println(expLen);
        short modLen = (short) modulusBytes.length;
        System.out.println(modLen);

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
  private final RSAPublicKey deserializeKey(byte[] buffer, short offset) {
        short expLen = bufferToShort(buffer, offset);
        short modLen = bufferToShort(buffer, (short) ((short) offset + (short)((short) 2 +expLen)));

        byte[] exponentBytes = Arrays.copyOfRange(buffer, offset+2, offset+2+expLen);
        byte[] modulusBytes = Arrays.copyOfRange(buffer, offset+4+expLen, offset+4+modLen+expLen);

        BigInteger exponent = new BigInteger(exponentBytes);
        BigInteger modulus = new BigInteger(modulusBytes);

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        try{
          KeyFactory kf = KeyFactory.getInstance("RSA");
          Key generatePublic = kf.generatePublic(keySpec);
          return (RSAPublicKey) generatePublic;
        }catch(Exception e){}
        System.out.println("KAPOT\nKAPOT\nKAPOT\nKAPOT\nKAPOT\nKAPOT\nKAPOT\nKAPOT\nKAPOT\nKAPOT\n");
        return globalPublicKey; //anders compiled het niet LOL
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

    String getText() {
        return display.getText();
    }

    void setText(String txt) {
        display.setText(txt);
    }

    void setText(int n) {
        setText(Integer.toString(n));
    }

    void setText(ResponseAPDU apdu) {
        byte[] data = apdu.getData();
        //System.out.println(apdu.toString());
            //TODO: Hier komen de APDU's uit. Hier dan maar identifiers inlezen?

        System.out.println("\n\n\nRECEIVING APDU:");
        System.out.println(new String(data));
        System.out.println(data.length);
        System.out.println("\n");


        for(int i = 0; i < data.length; i++)
        {
          System.out.print(data[i]);
          System.out.print(" ");
        }
        int sw = apdu.getSW();
        if (sw != 0x9000 || data.length < 5) {
            setText(MSG_ERROR);
        } else {
            setText((short) (((data[3] & 0x000000FF) << 8) | (data[4] & 0x000000FF)));


            //Dit is de apdu reader
            if (data[4] == 123){
              System.out.println("public key (deser): " + Base64.getEncoder().encodeToString(deserializeKey(data,(short)5).getEncoded()));
            }

            //Dit is de apdu reader
            if (data[4] == 92){
              //System.out.println("public key (deser): " + Base64.getEncoder().encodeToString(deserializeKey(data,(short)6).getEncoded()));
              try{
                Cipher decip = Cipher.getInstance("RSA");
                decip.init(Cipher.DECRYPT_MODE, globalPrivateKey);

                byte[] input = decip.doFinal(data, 5, 64);
                System.out.println("decrypted hallo : " + new String(input));
              }catch(Exception e){
                System.out.println("Failed to construct cipher!");
                System.out.println(e);
              }
            }


            setMemory(data[0] == 0x01);
        }
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
    	    					try {
    	    						Card card = c.connect("*");
    	    						try {
    	    							applet = card.getBasicChannel();
    	    							ResponseAPDU resp = applet.transmit(SELECT_APDU);
    	    							if (resp.getSW() != 0x9000) {
    	    								throw new Exception("Select failed");
    	    							}
    	    	    	    			setText(sendKey((byte) '='));
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
                char c = ((JButton) src).getText().charAt(0);
                setText(sendKey((byte) c));
            }
        } catch (Exception e) {
            System.out.println(MSG_ERROR);
        }
    }

    class CloseEventListener extends WindowAdapter {
        public void windowClosing(WindowEvent we) {
            System.exit(0);
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

    public ResponseAPDU sendKey(byte ins) {
      CommandAPDU apdu;
        switch(ins){
          case INST_CHARGING_REQUEST:
            byte[] data = shortToByteArray(generateNonce());

            System.out.println("--------------------");
            System.out.println((short) data[0]);
            System.out.println((short) data[1]);
            apdu = new CommandAPDU(0, ins, 0, 0, data);
            break;

          case INST_CHARGING_FINISH:
            apdu = new CommandAPDU(0, 'c', 0, 0, 42);
            break;
          case INST_PUMPING_AUTH:
            byte[] ser = serializeKey(globalPublicKey);
            apdu = new CommandAPDU(0, ins, 0, 0, ser);
            System.out.println(apdu.toString());
            System.out.println(ser.length);
            break;
          default:
            apdu = new CommandAPDU(0, ins, 0, 0, 42);
            break;
        }

        try {
      byte[] data = apdu.getData();
      System.out.println("\n\nSENT APDU:");
      for(int i = 0; i < data.length; i++)
      {
        System.out.print(data[i]);
        System.out.print(" ");
      }
			return applet.transmit(apdu);
		} catch (CardException e) {
			return null;
		}
    }

    public Dimension getPreferredSize() {
        return PREFERRED_SIZE;
    }

    public static void main(String[] arg) {
        JFrame frame = new JFrame(TITLE);
        Container c = frame.getContentPane();
        CalcTerminal panel = new CalcTerminal(frame);
        c.add(panel);
        frame.setResizable(false);
        frame.pack();
        frame.setVisible(true);
    }
}
