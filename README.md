1) Mikrotik настраиваем NetFlow v9 через меню IP - Traffik Flow
2) На целевой машине (коллекторе) через Wireshark захватываем трафик и сохраняем его в pcap файл.
3) В Терминале в папке с проектом вводи dotnet run sample.pcap --project .\NetFlowv9\NetFlowv9.csproj и загружаем в него сохраненный на шаге 2 pcap файл.
4) В папку с sample.pcap файлом будет сохранекн sample.json
5) Открываем в папке view index.html файл и загружаем из страницы json файл. Радуемся.