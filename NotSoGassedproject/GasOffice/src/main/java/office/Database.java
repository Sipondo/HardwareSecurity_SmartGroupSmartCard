package office;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;

import java.io.*;
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
            card = new Card(Integer.parseInt(values[0]), Integer.parseInt(values[1]), Integer.parseInt(values[2]));
            db.add(card);
            System.out.println(values[0] + values[1] + values[2]);
        }
        reader.close();
    }

    public void writeCSV(File file, ArrayList<Card> dataset)
            throws IOException {
        CSVWriter writer = new CSVWriter(new FileWriter(file));

        String[] values;
        for (Card card : db) {
            values = card.format();
            writer.writeNext(values);
        }

        writer.close();
    }

    public void add(Card card) {
        db.add(card);
    }

    public Card getCard(int id) {
        return db.get(id);
    }
}