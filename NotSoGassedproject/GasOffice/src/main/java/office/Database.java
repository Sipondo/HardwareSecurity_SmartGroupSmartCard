package office;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;

public class Database {

    File file = new File("NotSoGassedproject/GasOffice/db.csv");
    ArrayList<Card> db = new ArrayList<Card>();

    public Database() {
        try {
            file.createNewFile();
            readCSV(file);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void readCSV(File file) throws IOException {
        CSVReader reader = new CSVReader(new FileReader(file));
        String[] values;
        Card card;
        while ((values = reader.readNext()) != null) {
            card = new Card(Integer.parseInt(values[0]), Short.parseShort(values[1]), new BigInteger(values[2]), new BigInteger(values[3]), Integer.parseInt(values[4]));
            db.add(card);
        }
        reader.close();
    }

    public void writeCSV() throws IOException {
        CSVWriter writer = new CSVWriter(new FileWriter(file));
        String[] values;
        for (Card c : db) {
            values = c.format();
            writer.writeNext(values);
        }
        writer.close();
    }

    public void add(Card card) {
        if(!db.contains(card)) {
            db.add(card);
        }
        System.out.println("Card already exists in database.");
    }

    public Card getCard(int id)
    {
        for(Card c : db) {
            if (id == c.getId()) {
                return c;
            }
        }
        System.out.println("Card does not exist in database");
        return null;
    }
}