package office;

public class Card {

    private int id;
    private int allowance;
    private int pk;
    private int status = 1;

    Card(int id, int pk, int al) {
        this.id = id;
        this.pk = pk;
        setAllowance(al);
    }

    public int getID() {
        return id;
    }

    public int getPK() {
        return pk;
    }

    public void setAllowance(int al) {
        this.allowance = al;
    }

    public int getAllowance() {
        return allowance;
    }

    public void setStatus(int s) {
        this.status = s;
    }

    public int getStatus() {
        return status;
    }

    public String[] format() {
        return new String[] {String.format("%d",id),String.format("%d",pk),String.format("%d",status)};
    }
}
