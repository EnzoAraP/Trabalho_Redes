# Trabalho_Redes
Este Repositório se encontra o trabalho de Redes de Computadores, UFJF

Alunos: 
Enzo Araujo Pinheiro  
Renan Andrade Souraes Couri
Gabriel Toledo Gonc ̧alves Barreto 
Groo 27( pela numeração da planilha)

Orientações para executar:

O código foi feito em python, então precisa ter a linguagem instalada para rodá-lo. A versão mais antiga na qual este código foi rodado foi a 3.12.2, então, a partir desta, os intergantes do grupo podem afirmar ao leitor que o código funciona, ao menos em janeiro de 2026. 
IMPORTANTE: O código utiliza a biblioteca cryptography para fazer a cirptografia, que deve ser instalada, via "pip install cryptography" ou similar. 

Execução:

Além disso, antes de se executar os arquivos deve adentrar o diretório "codigos_trabalho". Dentro dele, deve-se executar, após instalar as bibliotecas necessárias, primeiro o arquivo do servidor com: "python server.py". Depois, pode-se executar um dos arquivos de cliente, o padrão(client.py), com controle de congestionamento, ou o client_noCC.py, sem controle de congestionamento, por meio de "python client.py" ou "python client_noCC.py"( após executar o do servidor). 

Pode-se definir a perda em LOSS_RATE(valor entre 0 e 1), ao fim do arquivo protocol.py(linha 75). Esta variável se encontra lá para homogenizar seu valor entre cliente e servidor. Ao fim da execução, aparecerá, ou será sobrescrito, um csv com os dados da vazão em mega bits/s pelo tempo, medido desde o início até o fim da passagem dos dados sintéticos. 


Plot:

Ao rodar o arquivo "t_plot_graficos_vazao", desde que o csvs correspondentes às taxas presentes no LOSS_RATE_VEC( aqui em porcentagem) no vetor existam em ambos os tipos de cliente, o com e o sem controle de congestionamento, aparecerão os gráficos um a um, sendo necessário fechar um para ver o próximo, e fechar o último para encerrar a execução do arquivo. É preciso ter as bibliotecas matplotlib e pandas instaladas para rodar o arquivo. Se não as tiver, pode baixá-las com "pip install matplotlib" e "pip install pandas". Além disso, as bibliotecas socket, random, time e struct são utilizadas no código. Se por algum motivo não as possuir( creio que algumas sejam nativas do python), pois instale-as, a fim de poder executar o código.