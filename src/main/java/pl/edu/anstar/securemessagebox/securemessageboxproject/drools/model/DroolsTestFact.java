package pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model;

public class DroolsTestFact {
    private String status;
    private boolean droolsIsWorking = false;

    public DroolsTestFact(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }

    public boolean isDroolsIsWorking() {
        return droolsIsWorking;
    }

    public void setDroolsIsWorking(boolean droolsIsWorking) {
        this.droolsIsWorking = droolsIsWorking;
    }
}