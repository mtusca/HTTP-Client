# Client HTTP - Administrare utilizatori și filme

Acest proiect implementează un client care interacționează prin HTTP cu serverul public oferit.  
Clientul permite administrarea utilizatorilor, autentificarea utilizatorilor obișnuiți, obținerea unui token JWT, precum și gestionarea filmelor și a colecțiilor.

## Structura proiectului
.
├── client.c - logica CLI și, de asemenea, toate comenzile
├── requests.c/h - constructori de cereri HTTP (GET/POST/PUT/DELETE)
├── helpers.c/h - utilitare socket + parsarea de răspuns
├── buffer.c/h - buffer folosit la recepția răspunsului
├── parson.c/h - bibliotecă JSON din enunțul temei
├── Makefile
└── README.md


## Descriere funcționalitate

Interacțiunea se bazează pe patru grupe de comenzi: `admin`, `user`, `filme` și `colecții`.

La primirea fiecărei comenzi, programul:
1. Solicită parametrii necesari de la utilizator.
2. Îi încorporează într-un mesaj HTTP.
3. Trimite mesajul către server prin `send_to_server`.
4. Primește răspunsul complet.
5. Extrage corpul JSON și afișează informațiile solicitate.

Pentru accesul la biblioteca de filme se folosește un **token JWT**.  
Un macro `NEED_TOKEN()` întrerupe rapid comenzile ce necesită autentificare, dacă token-ul lipsește, și afișează un mesaj de eroare.

ID-urile filmelor descărcate sunt stocate într-un **vector dinamic**.  
La crearea colecțiilor se poate verifica dacă un ID introdus de utilizator a fost deja obținut anterior.

## Bibliotecă JSON

Pentru parsarea și generarea obiectelor JSON, a fost utilizată biblioteca **Parson**, oferită în enunțul temei.  
Aceasta este:
- ușor de utilizat,
- portabilă,
- lipsită de dependențe externe,
- de dimensiune redusă.

---

