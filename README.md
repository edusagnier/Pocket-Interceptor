# Pocket-Interceptor

**Pocket-Interceptor** és una eina d’auditoria Wi-Fi desenvolupada en Bash, pensada per facilitar l’anàlisi, supervisió i atac en entorns de xarxes sense fils. Ofereix una interfície en terminal intuïtiva que simplifica tasques típiques de pentesting com l’activació del mode monitor, escaneig de xarxes, atac deauther, força bruta i desplegament de portals captius.

---
> [!IMPORTANT]
> Aquest programari ha estat desenvolupat per a **Kali Linux** i està **exclusivament destinat a finalitats educatives i d’auditoria de seguretat amb consentiment**.

> [!WARNING]
> **Requisit:** Es necessita una **targeta Wi-Fi compatible** amb mode monitor.

---

## Índex

- [Característiques](#característiques)
- [Requisits](#requisits)
- [Instal·lació](#instal·lació)
- [Avís Legal](#avís-legal)
- [Contacte](#contacte)

---

## Característiques

- [✓] **Activació i desactivació del mode monitor** de manera automàtica i segura.
- [✓] **Detecció de bandes suportades** (2.4 GHz, 5 GHz i 6 GHz) per la interfície seleccionada.
- [✓] **Menú interactiu** en terminal Per a millor gestion d'usuari.
- [✓] **Escaneig de xarxes Wifi** i selecció d'objectiu amb filtrat per canal i ESSID.
- [✓] **Escaneig de xarxa local** amb cerca de dispositius i vulnerabilitats (via `netscan.py`).
- [✓] **Dissenyat per a pentesters** que volen una eina ràpida, portable i funcional en Bash

### Mòduls d’atac integrats

- **Deautenticació** de dispositius (kick de clients de xarxes).
- **Captura de handshake WPA/WPA2** i atac de **força bruta**.
- **Atacs DoS** per denegar connexions sense fils.
- **Portal captiu fals** amb:
  - **Suplantació d'AP.**
  - Servidor **DHCP i DNS** manipulats.
  - **Phishing** de credencials mitjançant interfície web.
  - **Redirecció a BEeF Framework** per explotació del navegador víctima.

---
---
## Requisits que té el Pocket Interceptor
Hi ha un arxiu 'requirements.txt' que conté tots els programes neccesaris per el nostre software.


|      Deb Package     | Que fa aquesa                                           |
| :------------------- | :-------------------------------------------------------|
| `apache2`            | Per fer un servidor web per crear el portal cautiu.     |
| `iw`                 | Una eina que permet controlar.                          |
| `aircrack-ng`        | Es fa servir per poder modificar les terminals en GUI.  |
| `beef-xss`           | És l'eina principal per fer atacs els punts d'accessos. |
| `isc-dhcp-server`    | Fa un petit servidor dhcp per quan es fa la copia d'AP. |
| `dnsmasq`            | Servidor DNS per modificar certs dominis per el portal. |
| `php`                | El captive portal es necessita php per executar cmd.    |
| `hostapd`            | Crea un access point amb l'antena.                      |

---
---
## Instalació:
```bash
sudo ./install.sh #Només si vols instal·lar i no iniciar el programari.
sudo ./interceptor.sh #Instal·la tot les dependecies i ejecuta el programa.
```

---
##  Avís Legal

⚠️ Aquest projecte té com a únic propòsit la formació, recerca i auditoria de seguretat en entorns controlats i amb el consentiment explícit dels propietaris de les xarxes.
L'ús indegut d’aquesta eina en sistemes o xarxes sense autorització pot constituir una infracció greu de la legislació vigent, tant penal com civil. ⚠️

L’autor no es fa responsable de l'ús il·legal o no ètic que es pugui fer d’aquest programari.

⚠️ **Fes-lo servir sota la teva responsabilitat i sempre dins del marc legal.** ⚠️ 

---
## Contacte
Per a dubtes o millores contacta a l'equip de desenvolupament.
[Discord](https://discord.gg/3z7c5Cm3WD) 

---
Desenvolupat per:
- @edusagnier [Github](https://github.com/edusagnier)
- @janenti [Github](https://github.com/janenti)


---
© 2025 - Pocket Interceptor. Todos los derechos reservados.