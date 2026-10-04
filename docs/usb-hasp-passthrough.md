## USB HASP-ключ в devcontainer (Windows-хост, проверено)

Рабочий способ отдать однопользовательский USB-ключ HASP (Sentinel HL,
`0529:0001`) внутрь клиентской песочницы, чтобы 1С видела лицензию.
Проверено на: Windows 11 + Docker Desktop (WSL2 backend), платформа 1С
8.3.27.2342, ключ Sentinel USB Key.

Схема:

```text
Windows host (USB-ключ)
  │ usbipd bind + attach
  ▼
WSL-дистрибутив docker-desktop (/dev/bus/usb/00X/0YY)
  │ контейнер privileged → устройства видны после рестарта
  ▼
1c-ai-sandbox: /dev/bus/usb + aksusbd/hasplmd → /dev/aks/hasp → 1С
```

### 1) Хост: расшарить и приаттачить ключ

Нужен `usbipd` (подойдет сборка `usbipd-win`, в т.ч. RuDesktop).
Найти ключ:

```powershell
usbipd list
# BUSID  VID:PID    DEVICE
# 15-3   0529:0001  Sentinel USB Key   Not shared
```

Зашарить (требует администратора, вылезет UAC):

```powershell
usbipd bind --busid 15-3
```

Приаттачить в дистрибутив Docker Desktop (устройство станет видно
во всех WSL2-дистрибутивах):

```powershell
usbipd attach --wsl docker-desktop --busid 15-3
```

Проверка:

```powershell
wsl -d docker-desktop -e ls /dev/bus/usb
```

> Пока ключ приаттачен к WSL, хостовый `hasplms` его не видит —
> это нормально, ключ в монопольном владении у Docker.

Чтобы не повторять после перезагрузки, есть опция `--auto-attach`
(см. `usbipd attach --help`).

### 2) Контейнер: подхватить устройства

Контейнер песочницы запускается с `privileged: true`, но `/dev`
у него фиксируется на старте. Если ключ приаттачили позже —
перезапустить контейнер, устройства появятся:

```powershell
docker restart 1c-ai-sandbox
docker exec 1c-ai-sandbox ls -la /dev/bus/usb/
```

Найти ключ (наш: bus 1, dev 2):

```bash
docker exec 1c-ai-sandbox bash -c 'for d in /sys/bus/usb/devices/1-* /sys/bus/usb/devices/2-*; do [ -e "$d/idVendor" ] || continue; echo "$d $(cat $d/idVendor):$(cat $d/idProduct) bus=$(cat $d/busnum) dev=$(cat $d/devnum)"; done'
# /sys/bus/usb/devices/1-1 0529:0001 bus=1 dev=2
```

Нода устройства: `/dev/bus/usb/001/002` (major 189, minor `(bus-1)*128 + (dev-1)`).
Если ноды нет — создать вручную:

```bash
docker exec -u root 1c-ai-sandbox bash -c 'mknod /dev/bus/usb/001/002 c 189 1 && chmod 666 /dev/bus/usb/001/002'
```

### 3) Контейнер: драйвер HASP (aksusbd/hasplmd)

Проверен `haspd 8.53` от Etersoft (x86_64, встает на Ubuntu 24.04):

```text
https://download.etersoft.ru/pub/Etersoft/HASP/stable/x86_64/Ubuntu/22.04/haspd_8.53-eter1ubuntu_amd64.deb
```

Установка (внутри контейнера, от root):

```bash
docker cp haspd_8.53-eter1ubuntu_amd64.deb 1c-ai-sandbox:/tmp/haspd.deb
docker exec -u root 1c-ai-sandbox bash -c 'dpkg -i /tmp/haspd.deb; apt-get install -f -y'
```

Запуск демонов (systemd в контейнере нет — напрямую):

```bash
docker exec -u root 1c-ai-sandbox bash -c '/etc/init.d/haspd start; sleep 5; ps aux | grep -E "[a]ksusbd|[h]asplmd"'
```

Ноды ключей через udev (udevd тоже стартуем вручную):

```bash
docker exec -u root 1c-ai-sandbox bash -c 'pgrep -a udevd || (/usr/lib/systemd/systemd-udevd --daemon; sleep 2); udevadm trigger --subsystem-match=usb --action=add; sleep 3; ls /dev/aks/hasp/; ls -la /tmp/.aksusb'
```

Ожидание:

```text
/dev/aks/hasp/1-1
srw-rw-rw- 1 root root ... /tmp/.aksusb
```

### 4) Проверка: 1С видит лицензию

```bash
docker exec -u root 1c-ai-sandbox bash -c 'rm -rf /tmp/emptytest; DISPLAY=:99 timeout 120 /opt/1cv8/current/1cv8 CREATEINFOBASE File=/tmp/emptytest /Out /tmp/mkbase.log; tail -c 300 /tmp/mkbase.log'
# Создание информационной базы (...) успешно завершено
```

Файловая ИБ на 10 ГБ после этого открывается обычным клиентом,
Vanessa-тесты (`vrunner test vanessa --ibconnection "/F..."`) стартуют.

### Ограничения (честно)

- Все шаги внутри контейнера **эфемерны**: слетят при `Rebuild Container`.
  Для постоянства надо запечь `haspd` в `Dockerfile` и старт демонов
  в `entrypoint.sh` — это следующий шаг, не входит в этот гайд.
- `nethasp.ini` для этого сценария не нужен (ключ локальный для контейнера).
- Альтернатива без драйвера в контейнере: оставить ключ хосту
  (`hasplms` на Windows) и прописать в контейнерный `nethasp.ini`
  `NH_SERVER_ADDR=<IP хоста, доступный из контейнера>`
  (проверено через `host.docker.internal`, `http://...:1947` отвечает).
