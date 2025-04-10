package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"valx.pw/vapotol/internal/client"
)

func main() {
	
	var (
		serverAddr = flag.String("server", "127.0.0.1:8844", "Адрес VPN-сервера")
		localAddr  = flag.String("local", "127.0.0.1:1080", "Локальный SOCKS5 прокси")
		enableObfs = flag.Bool("obfs", true, "Включить обфускацию трафика")
		autoReconn = flag.Bool("reconnect", true, "Автоматически переподключаться")
	)
	flag.Parse()

	fmt.Println("VAPOtol VPN Client - valx.pw by c0re")
	fmt.Println("================================")
	fmt.Printf("Подключение к: %s\n", *serverAddr)
	fmt.Printf("Локальный прокси: %s\n", *localAddr)
	fmt.Printf("Обфускация: %v\n", *enableObfs)
	fmt.Printf("Автопереподключение: %v\n", *autoReconn)

	
	c, err := client.New(client.Options{
		ServerAddr: *serverAddr,
		LocalAddr:  *localAddr,
		EnableObfs: *enableObfs,
		AutoReconn: *autoReconn,
	})
	if err != nil {
		log.Fatalf("Ошибка инициализации клиента: %v", err)
	}

	
	go func() {
		if err := c.Start(); err != nil {
			log.Fatalf("Ошибка запуска клиента: %v", err)
		}
	}()

	
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nПолучен сигнал завершения. Отключаемся...")
	c.Stop()
	fmt.Println("Клиент остановлен. До свидания!")
} 