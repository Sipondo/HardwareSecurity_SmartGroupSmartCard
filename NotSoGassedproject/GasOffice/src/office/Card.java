package office;

public class Card {

    private int id;
    private short allowance;
    private Person person;

    Card(int id, short al, Person p) {
        this.id = id;
        this.allowance = al;
        this.person = p;
    }

    int getID() {
        return id;
    }

    short getAllowance() {
        return allowance;
    }

    Person getPerson() {
        return person;
    }

    int getPersonID() {
        return person.getID();
    }


}
