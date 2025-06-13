Acest proiect implementează un client care interacţionează prin HTTP cu serverul public oferit.
Clientul permite administrarea utilizatorilor, autentificarea de utilizatori obişnuiţi, obţinerea unui token JWT, precum şi gestionarea filmelor şi a colecţiilor.
.
├── client.c      - logica CLI şi, de asemenea, toate comenzile
├── requests.c/h  - constructori de cereri HTTP (GET/POST/PUT/DELETE)
├── helpers.c/h   - utilitare socket + parsarea de răspuns
├── buffer.c/h    - buffer folosit la recepţia răspunsului
├── parson.c/h    - bibliotecă JSON din enunţul temei
├── Makefile
└── README.md

Interacţiunea se bazează pe patru grupe de comenzi: admin, user, filme şi colecţii.
La primirea fiecăreia dintre comenzi, programul solicită parametrii, îi încorporează într-un mesaj HTTP şi îl trimite cu send_to_server. Răspunsul este citit integral, se extrage corpul JSON şi se afişează informaţia solicitată.
Pentru accesul la biblioteca de filme se foloseşte un token JWT. Macro-ul NEED_TOKEN() întrerupe rapid o comandă atunci când token-ul lipseşte şi afişează mesajul de eroare. ID-urile filmelor descărcate sunt stocate într-un vector dinamic. La crearea colecţiilor se poate verifica dacă un ID introdus de utilizator a fost obţinut anterior. Am ales biblioteca Parson pentru parsarea şi generarea obiectelor JSON oferită în enunţul temei, aceasta fiind uşor de utilizat, garantând portabilitatea arhivei şi absenţa dependenţelor externe. De asemenea, aceasta are o dimensiune mică.
