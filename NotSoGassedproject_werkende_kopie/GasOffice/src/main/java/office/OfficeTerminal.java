package office;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

public class OfficeTerminal {

    private Database carddb;
    public OfficeTerminal() {
        carddb = new Database();
    }

    void issueCard(Card card) {
        carddb.add(card);
    }

    void revokeCard(int id) {
        carddb.getCard(id).setStatus(0);
    }

    public static void main(String[] args) {
        OfficeTerminal ot = new OfficeTerminal();
        ot.issueCard(new Card(3, (short) 100, BigInteger.valueOf(2), BigInteger.valueOf(11)));
        ot.issueCard(new Card(4, (short) 93, BigInteger.valueOf(2), BigInteger.valueOf(12)));
        ot.issueCard(new Card(5, (short) 42, BigInteger.valueOf(2), BigInteger.valueOf(13)));
        ot.revokeCard(2);
        try {
            ot.carddb.writeCSV();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
