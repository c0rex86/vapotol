package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"valx.pw/vapotol/internal/server"
)

func main() {
	
	var (
		listenAddr     = flag.String("listen", ":8844", "Адрес для прослушивания")
		enableObfs     = flag.Bool("obfs", true, "Включить обфускацию трафика")
		enableMultiport = flag.Bool("multiport", true, "Использовать множество портов")
	)
	flag.Parse()

	fmt.Println("VAPOtol VPN Server - valx.pw by c0re")
	fmt.Println("================================")
	fmt.Printf("Слушаем на: %s\n", *listenAddr)
	fmt.Printf("Обфускация: %v\n", *enableObfs)
	fmt.Printf("Мультипорт: %v\n", *enableMultiport)

	
	s, err := server.New(server.Options{
		ListenAddr:    *listenAddr,
		EnableObfs:    *enableObfs,
		EnableMultiport: *enableMultiport,
	})
	if err != nil {
		log.Fatalf("Ошибка инициализации сервера: %v", err)
	}

	
	go func() {
		if err := s.Start(); err != nil {
			log.Fatalf("Ошибка запуска сервера: %v", err)
		}
	}()

	
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nПолучен сигнал завершения. Закрываем сервер...")
	s.Stop()
	fmt.Println("Сервер остановлен. До свидания!")
} 