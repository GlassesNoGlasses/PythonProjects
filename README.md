# Python Projects

## About
This portfolio represents a collection of personal Python projects I found interesting and wanted to pursue.

### Machine Learning
- [Snake AI](#snake-ai)
- [Weeb Recommendation AI](#weeb-recommendation-ai)

### Cybersecurity
- [Personal Firewall](#personal-firewall)
- [Firewall Simulation](#firewall-simulation)

### Others
- [Web Scraping](#web-scraping)


## Snake AI

Playing Snake can sometimes feel like TV channel surfing; pressing buttons and hoping something cool happens.
That's why I decided to make a snake AI to play snake for me, turning a mind-numbing experience into an
intense, exciting cheering experience. What will the snake do? When will it fail? Why does it keep going
around and around in circles? These are the questions you will ask yourself as you run the AI.

### Images
![alt text](https://github.com/GlassesNoGlasses/PythonProjects/blob/main/Snake/trials/collision_distance_trial1.png)

<img width="294" alt="image" src="https://github.com/user-attachments/assets/b862e38c-1d4d-42c4-abfc-93da9def6054">


### Dependencies
- PyTorch
- Pygame
- NumPy
- matplotlib
- random


## Weeb Recommendation AI

Have you ever binge-read that one manga series, only to end up finishing it and contemplating what you're
going to do with your life for the next hour? Need another series to escape into but not sure what to pick?
Have I got the solution for you! Input the mangas you've read into the model and get similar mangas based
on genres, demographic, and MyAnimeList ratings. The model works on a custom neuron with its own weights and
biases, as well as back-propagation after a user selection.

### Dependencies
- Pandas
- NumPy
- nltk
- matplotlib


## Personal Firewall

A personal firewall for network layer traffic. Specify the IP addresses of machines, inbound/outbound traffic
rules, as well as protocols to allow/block. Packets are sniffed using the `scapy` library, and can be saved
as a `.pcap` file.


### Dependencies
- Scapy
- Pandas
- ipaddress
- socket

## Firewall Simulation

A simulation of a firewall using sockets and multithreading. TCP/IP packets are created from scratch and sent
from the host to a sender or vice-versa. Information is then logged in `firewall.log`. Configure the
firewall using `config.py`.


Note: For Mac and Linux, `sudo` maybe required to run `sim.py`.

### Images
Console:
<img width="327" alt="image" src="https://github.com/user-attachments/assets/d5852d37-8770-4b80-87c9-c94de3476803">

Logs:
<img width="707" alt="image" src="https://github.com/user-attachments/assets/b97c9089-a396-4403-a18f-11c767385d00">

Firewall CSV Config:
<img width="259" alt="image" src="https://github.com/user-attachments/assets/f1bee42d-8a57-420d-b1cd-37a5a25f3a1b">


### Dependencies
- Pandas
- socket
- threading
- struct
- time
- ipaddress
- random

## Web Scraping

A simple web scraping program using `selenium` and `BeautifulSoup`.

### Dependencies:
- Selenium
- BeautifulSoup
- time


