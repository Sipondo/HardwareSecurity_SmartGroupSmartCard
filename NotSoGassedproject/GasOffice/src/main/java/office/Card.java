package office;

import java.math.BigInteger;

public class Card {

    private int id, status = 1;
    private short allowance;
    private BigInteger pkg, pke;

    Card(int id, short al, BigInteger pkg, BigInteger pke) {
        this.id = id;
        this.pkg = pkg;
        this.pke = pke;
        setAllowance(al);
    }

    Card(int id, short al, BigInteger pkg, BigInteger pke, int status) {
        this.id = id;
        this.pkg = pkg;
        this.pke = pke;
        setAllowance(al);
        setStatus(status);
    }

    public int getId() {
        return id;
    }

    public BigInteger getPkg() {
        return pkg;
    }

    public BigInteger getPke() {
        return pke;
    }

    public void setAllowance(short al) {
        this.allowance = al;
    }

    public short getAllowance() {
        return allowance;
    }

    public void setStatus(int s) {
        this.status = s;
    }

    public int getStatus() {
        return status;
    }

    public String[] format() {
        return new String[] {String.format("%d",id),String.format("%d", allowance),String.format("%d",pkg),String.format("%d",pke),String.format("%d",status)};
    }
}
