package com.example.jnidemo;

import androidx.appcompat.app.AppCompatActivity;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    // ─── JNI Declarations ────────────────────────────────────────────────────

    public native String helloFromJNI();
    public native int factorial(int n);

    // ─── Fields ──────────────────────────────────────────────────────────────

    private final NativeSecurityManager drk_securityManager = new NativeSecurityManager();

    private TextView drk_tvStatus;
    private TextView drk_tvHello;
    private TextView drk_tvFact;

    // ─── Lifecycle ───────────────────────────────────────────────────────────

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bindViews();
        applySecurityGate();
    }

    // ─── View Binding ────────────────────────────────────────────────────────

    private void bindViews() {
        drk_tvStatus = findViewById(R.id.drk_tvStatus);
        drk_tvHello  = findViewById(R.id.drk_tvHello);
        drk_tvFact   = findViewById(R.id.drk_tvFact);
    }

    // ─── Security Gate ───────────────────────────────────────────────────────

    private void applySecurityGate() {
        int drk_status = drk_securityManager.getSecurityStatus();

        if (drk_status != NativeSecurityManager.STATUS_OK) {
            showSecurityAlert(drk_status);
        } else {
            showSecureContent();
        }
    }

    private void showSecurityAlert(int drk_status) {
        drk_tvStatus.setTextColor(Color.RED);
        drk_tvStatus.setText(resolveAlertMessage(drk_status));

        drk_tvHello.setText("Fonction native sensible désactivée");
        drk_tvFact.setText("Calcul natif bloqué");
    }

    private void showSecureContent() {
        drk_tvStatus.setText("Etat sécurité : OK");
        drk_tvStatus.setTextColor(Color.parseColor("#2E7D32"));

        drk_tvHello.setText(helloFromJNI());

        int drk_result = factorial(10);
        drk_tvFact.setText(drk_result >= 0
                ? "Factoriel de 10 = " + drk_result
                : "Erreur factoriel");
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private String resolveAlertMessage(int drk_status) {
        switch (drk_status) {
            case NativeSecurityManager.STATUS_TRACE_DETECTED:
                return "ALERTE : Debug / ptrace détecté";
            case NativeSecurityManager.STATUS_MAPS_SUSPICIOUS:
                return "ALERTE : Signatures suspectes (Frida/Magisk)";
            case NativeSecurityManager.STATUS_MULTIPLE_SIGNALS:
                return "ALERTE CRITIQUE : Environnement compromis";
            default:
                return "Etat sécurité : Suspect";
        }
    }
}