# Carnage - TryHackMe

[link do zadania](https://tryhackme.com/room/c2carnage)

## Treść:

```
Eric Fischer from the Purchasing Department at Bartell Ltd has received an email from a known contact with a Word document attachment.  Upon opening the document, he accidentally clicked on "Enable Content."  The SOC Department immediately received an alert from the endpoint agent that Eric's workstation was making suspicious connections outbound. The pcap was retrieved from the network sensor and handed to you for analysis. 

Task: Investigate the packet capture and uncover the malicious activities. 
```

## 1. Identyfikacja hosta (Eric Fisher)

Na początek najlepiej będzie zidentyfikować maszynę na której pracował Eric Fisher aby uniknąć przeglądania zbędnych pakietów. Możemy to zweryfikować wchodząć w **Statystyki -> Punkty końcowe** i posortować malejąco wg. ilości wysłanych pakietów.

![](/img/ss/1.png)

Żeby się upewnić, który to może być sprawdźmy również **Statystyki -> Konwersacji**

![](/img/ss/2.png)

Teraz możemy założyć że IP **10.9.23.102** należy do komputera z którego pracował Eric.


## 2. Identyfikacja złośliwego IP

Z opisu wiemy, że 10.9.23.102 nawiązało połączenie z jakimś zewnętrznym serwerem, więc możemy zakłożyć że zrobiono to poprzez HTTP(dodatkowo pierwsze pytanie **"What was the date and time for the first HTTP connection to the malicious IP?"** nam to podpowiada).

Filtr: `http && ip.addr==10.9.23.102`

Przejdziemy do zakładki **Konwersacje** i pozostaje nam 5 adresów. 

![](/img/ss/3.png)

Aby przekonać się, którego z nich szukamy możemy sprawdzić je w [VirusTotal](https://www.virustotal.com/
). Po wpisaniu wszystkich dwa zostały oznaczone jako złośliwe
* [185.106.96.158](https://www.virustotal.com/gui/ip-address/185.106.96.158)
* [85.187.128.24](https://www.virustotal.com/gui/ip-address/85.187.128.24)

P.S. 
* 85.187.128.24 - z niego pobrano złośliwy plik
* 185.106.96.158 - z nim makro z pliku próbowało nawiązać kontakt

Patrząc na historię logów wg numeru jako pierwsze zapytanie HTTP pokazuje nam się pakiet nr 1656, który zawiera odpowiedź do pierwszego pytania, natomiast pakiet 1735 posiada odpowiedź do pytania nr 2.

### Odpowiedzi - pyt. 1, 2, 3
*1. What was the date and time for the first HTTP connection to the malicious IP?* - *"2021-09-24 16:44:38"*

*2. What is the name of the zip file that was downloaded?* - *documents.zip*

Aby odpowiedzieć na pytanie nr 3 trzeba wejść w pakiet **1735 -> HTTP -> Host**

*3. What was the domain hosting the malicious zip file?* - *attirenepal.com*

4 *"Without downloading the file, what is the name of the file in the zip file?"* - by odpowiedzieć na te pytanie należy wiedzieć, [jak czytać początkowe bajty pliku .zip](https://en.wikipedia.org/wiki/ZIP_(file_format)). W naszym przypadku w wiresharku najlepiej przejść do pakietu 1735 "Follow HTTP stream" i poszukać pierwszych nagłówka **"PK"**. Po nim będzie napisana nazwa pliku i jego rozszerzenie. 
![](/img/odp/2.png)

*Odp: chart-1530076591.xls*

## 3. Zbadanie pliku documents.zip

Aby wyodrębnić plik należy wejść **Plik -> Eksportuj obiekt -> HTTP**, filtrujemy po nazwie "attirenepal.com". Teoretycznie samo pobranie pliku nie wywoływało zainfekowania urządzenia, jednak dla bezpieczeństwa lepiej jest przerzucić plik do **Sandboxa**. Ja pracuję na Windows 11 Pro, więc w tej wersji dostępny jest **Windows Sandbox**. 

![](/img/ss/4.png)


```powershell
# Komenda generująca skrót SHA-256

Get-FileHash .\chart-1530076591.xls -Algorithm SHA256
```

```
SHA-256: 2EA1B06DE7BC93F2165DB2AC29A9C964716F17415472497B31BE4062BB639240
```

[Wyszukanie w VirusTotal](https://www.virustotal.com/gui/file/2ea1b06de7bc93f2165db2ac29a9c964716f17415472497b31be4062bb639240)

W analizie od VirusTotal w sekcji **Contacted Domains** możemy znaleźć również odpowiedź na pytanie nr 5.

![](/img/odp/4.png)

5 *Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved with this activity?* - *finejewels.com.au, new.americold.com, thietbiagt.com*

### Analiza ruchu w Wiresharku

Plik podstawowy rodzieliłem na dwa:
* `malicious_file_download_traffic.pcap` - plik zawierający komunikację między IP 10.9.23.102(maszyna Erica), a IP 85.187.128.24(serwer z którego pobrano złośliwy plik .xls). Ten plik nam się na razie nie przyda.

* `eric_and_c2_server_comms.pcap` - plik zawierający komunikację między IP 10.9.23.102(maszyna Erica), a IP 185.106.96.158, z którym komunikację nawiązało makro po uruchomieniu pliku .xls. Ten plik jest teraz dla nas kluczowy ponieważ będziemy analizować wszystkie połączenia i dane jakie wymieniły między sobą maszyny.


![](/img/ss/5.png)
*Zrzut ekranu z pliku eric_and_c2_server_comms.pcap*

Jako pierwsze zapytanie GET(pakier nr 1) widzimy zapytanie o plik `cacerts.crl`. Plik z rozszerzeniem .crl (Certificate Revocation List – lista unieważnionych certyfikatów) to podpisana cyfrowo przez urząd certyfikacji (CA) lista certyfikatów X.509, które zostały unieważnione przed upływem ich terminu ważności (np. z powodu wycieku klucza prywatnego).

6 *Which certificate authority issued the SSL certificate to the first domain from the previous question?* - *verisign*

