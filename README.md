This respository contain main.c file that simulate a DNS server protocol that can be integrated with standart host DNS protocol or custom DNS protocols.
Our protocol recieve and send packets using socket programming.
Compiling anf running were tested in GNS3 environment with ubuntu virtual box VMs.

key features:
1) Custom listenning port.
2) static host entery database.
3) Option to forward the query to another DNS server if entery not found using the forwarding flag in the code.
4) Identification of the DNS packets via Wireshark.

Running instructions fur linux machine:
In the terminal enter to location were main.c file is presented and run the command: gcc -o "compilation_name" ./main.c .
replace 'compilation_name' with your compilation file name and run the command: ./"compilation_name" .
then the server should be up and running.
