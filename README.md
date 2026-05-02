# Lab 23 — JNI Demo · Couche Sécurité Anti-Debug

> Extension du **Lab 22** — ajout d'une couche de sécurité native implémentée en C via JNI.  
> Ce lab introduit les techniques de détection d'environnements compromis (debugger, Frida, Magisk) directement depuis le code natif, sans dépendance à l'API Android.
> Auteur: MADILI Kenza
---

## Objectifs

- Comprendre les vecteurs d'attaque courants sur les apps Android natives (ptrace, Frida, Magisk)
- Implémenter des détections anti-debug côté natif (C/C++) plutôt que Java
- Structurer une **security gate** qui bloque l'exécution des fonctions sensibles si l'environnement est compromis
- Exposer un statut de sécurité typé via JNI vers la couche Java

---

## Ce qui change par rapport au Lab 22

| Élément | Lab 22 | Lab 23 |
|---|---|---|
| Sécurité | Aucune | Couche native anti-debug |
| Accès aux fonctions JNI | Direct | Conditionnel au statut sécurité |
| Classe Java ajoutée | — | `NativeSecurityManager.java` |
| Fichier C ajouté | — | `security.cpp` |
| Codes de statut | — | `STATUS_OK`, `STATUS_TRACE_DETECTED`, `STATUS_MAPS_SUSPICIOUS`, `STATUS_MULTIPLE_SIGNALS` |
| Interface | Résultats directs | Alerte rouge si compromis, résultats si OK |

---

## Structure du projet

```
JNIDemo/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/com/example/jnidemo/
│   │   │   │   ├── MainActivity.java            # Activité avec security gate
│   │   │   │   └── NativeSecurityManager.java   # Wrapper Java ↔ C sécurité
│   │   │   ├── cpp/
│   │   │   │   ├── native-lib.cpp               # Fonctions JNI du Lab 22
│   │   │   │   ├── security.cpp                 # Détections anti-debug (nouveau)
│   │   │   │   └── CMakeLists.txt               # Mis à jour avec security.cpp
│   │   │   └── res/layout/
│   │   │       └── activity_main.xml            # UI avec statut sécurité
│   └── build.gradle
└── README.md
```

---

<img width="1080" height="2340" alt="WhatsApp Image 2026-05-02 at 00 33 07" src="https://github.com/user-attachments/assets/05ebc359-0f95-491f-8d64-7bdd578fef87" />

## Nouvelle classe : `NativeSecurityManager`

Wrapper Java qui expose les constantes de statut et délègue la détection au code natif.

```java
public class NativeSecurityManager {

    public static final int STATUS_OK               = 0;
    public static final int STATUS_TRACE_DETECTED   = 1;
    public static final int STATUS_MAPS_SUSPICIOUS  = 2;
    public static final int STATUS_MULTIPLE_SIGNALS = 3;

    static {
        System.loadLibrary("native-lib");
    }

    public native int getSecurityStatus();
}
```

---

## Techniques de détection implémentées

### 1. Détection ptrace / TracerPid

Lecture de `/proc/self/status` pour détecter si un processus externe trace l'application.  
Un `TracerPid` non nul indique qu'un debugger est attaché.

```c
int drk_checkTracerPid() {
    FILE *f = fopen("/proc/self/status", "r");
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) return 1; // debugger détecté
        }
    }
    fclose(f);
    return 0;
}
```

### 2. Détection de signatures suspectes dans `/proc/self/maps`

Analyse des mappings mémoire du processus pour repérer les signatures de frameworks d'instrumentation dynamique.

Signatures recherchées :

| Signature | Outil ciblé |
|---|---|
| `frida` | Frida (instrumentation dynamique) |
| `xposed` | Xposed Framework |
| `magisk` | Magisk (root) |
| `substrat` | Substrate (hooking) |

```c
int drk_checkMaps() {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    const char *suspects[] = {"frida", "xposed", "magisk", "substrat"};
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; i < 4; i++) {
            if (strstr(line, suspects[i])) return 1;
        }
    }
    fclose(f);
    return 0;
}
```

### 3. Détection multi-signaux

Si plusieurs indicateurs sont détectés simultanément, le statut passe à `STATUS_MULTIPLE_SIGNALS` — niveau de menace critique indiquant un environnement activement compromis.

---

## Logique de la security gate

```
getSecurityStatus()
       │
       ├── TracerPid != 0 ──────────────────────► STATUS_TRACE_DETECTED
       │
       ├── Maps suspectes ──────────────────────► STATUS_MAPS_SUSPICIOUS
       │
       ├── TracerPid != 0 ET Maps suspectes ───► STATUS_MULTIPLE_SIGNALS
       │
       └── Aucune anomalie ─────────────────────► STATUS_OK
```

---

## Comportement de l'interface selon le statut

| Statut | Couleur | Message affiché | Fonctions natives |
|---|---|---|---|
| `STATUS_OK` | Vert `#2E7D32` | Etat sécurité : OK | Activées |
| `STATUS_TRACE_DETECTED` | Rouge | ALERTE : Debug / ptrace détecté | Désactivées |
| `STATUS_MAPS_SUSPICIOUS` | Rouge | ALERTE : Signatures suspectes (Frida/Magisk) | Désactivées |
| `STATUS_MULTIPLE_SIGNALS` | Rouge | ALERTE CRITIQUE : Environnement compromis | Désactivées |

<img width="917" height="441" alt="logcat" src="https://github.com/user-attachments/assets/f5540328-b58d-49de-ad5c-079d50fb1052" />

---

## Modifications dans `MainActivity`

La logique d'affichage est désormais conditionnée par le résultat de `getSecurityStatus()` :

```java
private void applySecurityGate() {
    int status = drk_securityManager.getSecurityStatus();
    if (status != NativeSecurityManager.STATUS_OK) {
        showSecurityAlert(status);
    } else {
        showSecureContent();
    }
}
```

En cas d'alerte, `helloFromJNI()` et `factorial()` ne sont **jamais appelés** — les fonctions sensibles restent inaccessibles.

---

## Mise à jour CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.22.1)
project("native-lib")

add_library(
    native-lib SHARED
    native-lib.cpp
    security.cpp        # Ajouté au Lab 23
)

find_library(log-lib log)
target_link_libraries(native-lib ${log-lib})
```

---

## Tester les détections

| Scénario de test | Résultat attendu |
|---|---|
| Lancer sur émulateur standard | `STATUS_OK` |
| Attacher un debugger LLDB/GDB | `STATUS_TRACE_DETECTED` |
| Injecter Frida (`frida-server`) | `STATUS_MAPS_SUSPICIOUS` |
| Appareil rooté avec Magisk visible | `STATUS_MAPS_SUSPICIOUS` |
| Frida + debugger simultanés | `STATUS_MULTIPLE_SIGNALS` |

---

## Prérequis

Identiques au Lab 22, avec en supplément :

- Connaissance de base du système de fichiers `/proc` Linux
- Frida ou un émulateur rooté pour tester les cas d'alerte (optionnel)

---

## Limites et perspectives

Ces détections constituent une **première couche de défense** — elles restent contournables par un attaquant expérimenté (hook de `fopen`, patch mémoire, etc.). Les techniques avancées qui dépassent ce lab incluent :

- Vérification d'intégrité du binaire (checksum natif)
- Détection de hooks sur les fonctions système (`strcmp`, `fopen`)
- Obfuscation du code natif (LLVM-obfuscator)
- Certificate pinning côté réseau

---

*Lab 23 — Sécurité Mobile · Extension directe du Lab 22 · Anti-debug natif via JNI et `/proc`.*
