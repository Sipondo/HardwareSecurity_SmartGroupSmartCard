package office;

import java.io.File;
import java.io.IOException;

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
        ot.issueCard(new Card(0, 0, 100));
        ot.issueCard(new Card(1, 10, 100));
        ot.issueCard(new Card(2, 11, 98));
        try {
            ot.carddb.writeCSV(new File("NotSoGassedproject/GasOffice/db.csv"), ot.carddb.db);
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
