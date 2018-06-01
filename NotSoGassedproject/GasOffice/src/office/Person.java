package office;

public class Person {

    private String name;
    private int id;
    private Card card = null;

    Person(String name, int id) {
        this.name = name;
        this.id = id;
    }

    String getName() {
        return name;
    }

    int getID() {
        return id;
    }

    void setcard(Card card) {
        this.card = card;
    }

    int getCardID() {
        return card.getID();
    }
}
