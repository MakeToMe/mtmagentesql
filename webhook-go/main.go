package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type BanRequest struct {
	IP      string         `json:"ip"`
	BanList []struct {
		IP2Ban string `json:"ip2ban"`
	} `json:"ban_list"`
}

type DockerStatsRequest struct {
	IP        string          `json:"ip"`
	Stats     json.RawMessage `json:"stats"`
	Timestamp string          `json:"timestamp"`
}

type VMStatsRequest struct {
	IP               string          `json:"ip"`
	MemTotal        float64         `json:"mem_total"`
	MemUsada        float64         `json:"mem_usada"`
	MemUsadaP       float64         `json:"mem_usada_p"`
	MemDisponivel   float64         `json:"mem_disponivel"`
	MemDisponivelP  float64         `json:"mem_disponivel_p"`
	CPUTotal        float64         `json:"cpu_total"`
	CPULivre        float64         `json:"cpu_livre"`
	CPUUsada        float64         `json:"cpu_usada"`
	DiscoTotal      float64         `json:"disco_total"`
	DiscoUsado      float64         `json:"disco_usado"`
	DiscoLivre      float64         `json:"disco_livre"`
	DiscoUsoP       float64         `json:"disco_uso_p"`
	DiscoLivreP     float64         `json:"disco_livre_p"`
	CPUCores        json.RawMessage `json:"cpu_cores"`
	Timestamp       string          `json:"timestamp"`
}

type Servidor struct {
	UID     string
	Titular string
	IP      string
}

type FirewallStatusRequest struct {
	IP           string `json:"ip"`
	FirewallType string `json:"firewall_type"`
	Active       bool   `json:"active"`
}

type FirewallRuleRequest struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	Action       string `json:"action"`
	Description  string `json:"description,omitempty"`
	Source       string `json:"source,omitempty"`
	Active       bool   `json:"active"`
	Priority     int    `json:"priority,omitempty"`
	FirewallType string `json:"firewall_type"`
}

type Process struct {
	PID        int     `json:"pid"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	RAMPercent float64 `json:"ram_percent"`
	RSSKB      int     `json:"rss_kb"`
	Command    string  `json:"command"`
	Rank       int     `json:"rank"`
}

type TopProcesses struct {
	ByCPU []Process `json:"by_cpu"`
	ByRAM []Process `json:"by_ram"`
}

type ServerInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type SystemMetrics struct {
	CPUCores    json.RawMessage `json:"cpu_cores"`
	CPUTotal    float64         `json:"cpu_total"`
	CPUUsada    float64         `json:"cpu_usada"`
	CPULivre    float64         `json:"cpu_livre"`
	MemTotal    float64         `json:"mem_total"`
	MemUsada    float64         `json:"mem_usada"`
	MemLivre    float64         `json:"mem_livre"`
	DiscoTotal  float64         `json:"disco_total"`
	DiscoUsado  float64         `json:"disco_usado"`
	DiscoLivre  float64         `json:"disco_livre"`
}

type ProcessMetricsRequest struct {
	// Campos no formato antigo (com ServerInfo)
	ServerInfo   *ServerInfo   `json:"server_info,omitempty"`
	
	// Campos no formato novo (com server_ip e hostname no nível raiz)
	ServerIP     string        `json:"server_ip,omitempty"`
	Hostname     string        `json:"hostname,omitempty"`
	
	// Campo de processos - aceita tanto "top_processes" quanto "processes"
	TopProcesses TopProcesses  `json:"top_processes"`
	Processes    *TopProcesses `json:"processes,omitempty"`
	
	SystemMetrics SystemMetrics `json:"system_metrics"`
}

type ConfigRequest struct {
	IP      string  `json:"ip"`
	CPU     float64 `json:"cpu,omitempty"`
	RAM     float64 `json:"ram,omitempty"`
	Storage float64 `json:"storage,omitempty"`
	Sistema string  `json:"sistema,omitempty"`
	Papel   string  `json:"papel,omitempty"`
}

func getClientIP(r *http.Request) string {
	// Tenta pegar o IP real do cliente (caso use proxy)
	xForwarded := r.Header.Get("X-Forwarded-For")
	if xForwarded != "" {
		ips := strings.Split(xForwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func main() {
	log.Println("[webhook-go] Iniciando serviço...")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	log.Printf("[webhook-go] Variáveis de conexão: host=%s port=%s user=%s db=%s", host, port, user, dbname)
	connStr := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname)
	
	// Abrir o pool de conexões
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("[webhook-go] Erro ao conectar no banco: %v", err)
	}
	
	// Configurar o pool de conexões
	db.SetMaxOpenConns(25)                    // Máximo de conexões abertas simultaneamente
	db.SetMaxIdleConns(10)                    // Máximo de conexões ociosas no pool
	db.SetConnMaxLifetime(5 * time.Minute)    // Tempo máximo de vida de uma conexão
	db.SetConnMaxIdleTime(1 * time.Minute)    // Tempo máximo que uma conexão pode ficar ociosa
	
	// Verificar se a conexão está funcionando
	if err := db.Ping(); err != nil {
		log.Fatalf("[webhook-go] Erro ao verificar conexão com o banco: %v", err)
	}
	
	log.Println("[webhook-go] Pool de conexões com o banco criado com sucesso")
	
	// Log do search_path para diagnóstico
	var searchPath string
	err = db.QueryRowContext(context.Background(), "SHOW search_path").Scan(&searchPath)
	if err != nil {
		log.Printf("[webhook-go] Erro ao obter search_path: %v", err)
	} else {
		log.Printf("[webhook-go] search_path atual: %s", searchPath)
	}
	
	// Monitoramento do pool de conexões
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		
		for range ticker.C {
			stats := db.Stats()
			log.Printf("[webhook-go] Estatísticas do pool: conexões abertas=%d, em uso=%d, ociosas=%d",
				stats.OpenConnections, stats.InUse, stats.Idle)
		}
	}()
	
	defer db.Close()

	http.HandleFunc("/listbanip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		var req BanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		// Consulta whitelist na tabela servidores usando o campo 'ip' do JSON
		var srv Servidor
		query := `SELECT uid, titular, ip FROM mtm.servidores WHERE TRIM(LOWER(ip)) = TRIM(LOWER($1)) LIMIT 1`
		err := db.QueryRowContext(context.Background(), query, req.IP).Scan(&srv.UID, &srv.Titular, &srv.IP)
		if err != nil {
			log.Printf("[webhook-go] Erro ao buscar servidor com IP '%s': %v", req.IP, err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("servidor não encontrado"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(srv)
		// Funções de debug e auditoria removidas para reduzir volume de logs e I/O
		// Gravação no banco dos IPs banidos
		for _, item := range req.BanList {
			// Insere o registro na tabela banned_ips
			// Aproveita os valores padrão do banco para id, created_at, updated_at e active
			// Usa ON CONFLICT para evitar duplicidade de IP banido para o mesmo servidor_id
			_, err := db.ExecContext(context.Background(),
				`INSERT INTO mtm.banned_ips (servidor_id, titular, servidor_ip, ip_banido) 
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (servidor_id, ip_banido) 
				WHERE servidor_id IS NOT NULL AND ip_banido IS NOT NULL
				DO UPDATE SET 
				  updated_at = NOW(), 
				  active = true`,
				srv.UID, srv.Titular, srv.IP, item.IP2Ban)
			
			if err != nil {
				log.Printf("[webhook-go] Erro ao inserir IP banido %s: %v", item.IP2Ban, err)
			} else {
						// Log de sucesso removido para reduzir volume
			}
		}
	})

	// Rota para receber estatísticas da VM
	http.HandleFunc("/vm_stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		
		var req VMStatsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("[webhook-go] Erro ao decodificar JSON: %v", err)
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		
		// Consulta whitelist na tabela servidores usando o campo 'ip' do JSON
		var srv Servidor
		query := `SELECT uid, titular, ip FROM mtm.servidores WHERE TRIM(LOWER(ip)) = TRIM(LOWER($1)) LIMIT 1`
		err := db.QueryRowContext(context.Background(), query, req.IP).Scan(&srv.UID, &srv.Titular, &srv.IP)
		if err != nil {
			log.Printf("[webhook-go] Erro ao buscar servidor com IP '%s': %v", req.IP, err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("servidor não encontrado"))
			return
		}
		
		// Insere as estatísticas na tabela vm_stats
		_, err = db.ExecContext(context.Background(),
			`INSERT INTO mtm.vm_stats (
				titular, ip, mem_total, mem_usada, mem_usada_p, mem_disponivel, mem_disponivel_p,
				cpu_total, cpu_livre, cpu_usada, disco_total, disco_usado, disco_livre, disco_uso_p, disco_livre_p,
				cpu_cores
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			srv.Titular, req.IP, 
			math.Round(req.MemTotal*1000)/1000, 
			math.Round(req.MemUsada*1000)/1000, 
			math.Round(req.MemUsadaP*1000)/1000, 
			math.Round(req.MemDisponivel*1000)/1000, 
			math.Round(req.MemDisponivelP*1000)/1000,
			math.Round(req.CPUTotal*1000)/1000, 
			math.Round(req.CPULivre*1000)/1000, 
			math.Round(req.CPUUsada*1000)/1000, 
			math.Round(req.DiscoTotal*1000)/1000, 
			math.Round(req.DiscoUsado*1000)/1000, 
			math.Round(req.DiscoLivre*1000)/1000, 
			math.Round(req.DiscoUsoP*1000)/1000, 
			math.Round(req.DiscoLivreP*1000)/1000,
			req.CPUCores)
		
		if err != nil {
			log.Printf("[webhook-go] Erro ao inserir estatísticas da VM: %v", err)
			http.Error(w, "Erro ao salvar estatísticas", http.StatusInternalServerError)
			return
		}
		
		// Log de sucesso removido para reduzir volume
		
		// Retorna os dados do servidor como resposta
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(srv)
		
		// Função de debug removida para reduzir volume de logs e I/O
	})

	// Rota para receber estatísticas do Docker
	http.HandleFunc("/docker_stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		
		var req DockerStatsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("[webhook-go] Erro ao decodificar JSON: %v", err)
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		
		// Consulta whitelist na tabela servidores usando o campo 'ip' do JSON
		var srv Servidor
		query := `SELECT uid, titular, ip FROM mtm.servidores WHERE TRIM(LOWER(ip)) = TRIM(LOWER($1)) LIMIT 1`
		err := db.QueryRowContext(context.Background(), query, req.IP).Scan(&srv.UID, &srv.Titular, &srv.IP)
		if err != nil {
			log.Printf("[webhook-go] Erro ao buscar servidor com IP '%s': %v", req.IP, err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("servidor não encontrado"))
			return
		}
		
		// Insere as estatísticas na tabela docker_stats
		_, err = db.ExecContext(context.Background(),
			`INSERT INTO mtm.docker_stats (titular, ip, stats) VALUES ($1, $2, $3)`,
			srv.Titular, req.IP, req.Stats)
		
		if err != nil {
			log.Printf("[webhook-go] Erro ao inserir estatísticas Docker: %v", err)
			http.Error(w, "Erro ao salvar estatísticas", http.StatusInternalServerError)
			return
		}
		
		// Log de sucesso removido para reduzir volume
		
		// Retorna os dados do servidor como resposta
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(srv)
		
		// Função de debug removida para reduzir volume de logs e I/O
	})

	// Rota para receber status do firewall
	http.HandleFunc("/firewall_status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		
		var req FirewallStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("[webhook-go] Erro ao decodificar JSON: %v", err)
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		
		// Consulta whitelist na tabela servidores usando o campo 'ip' do JSON
		var srv Servidor
		query := `SELECT uid, titular, ip FROM mtm.servidores WHERE TRIM(LOWER(ip)) = TRIM(LOWER($1)) LIMIT 1`
		err := db.QueryRowContext(context.Background(), query, req.IP).Scan(&srv.UID, &srv.Titular, &srv.IP)
		if err != nil {
			log.Printf("[webhook-go] Erro ao buscar servidor com IP '%s': %v", req.IP, err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("servidor não encontrado"))
			return
		}
		
		// Insere ou atualiza o status do firewall
		_, err = db.ExecContext(context.Background(),
			`INSERT INTO mtm.firewall_status (
				servidor_id, titular, firewall_type, active, servidor_ip
			) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (servidor_id) 
			DO UPDATE SET 
				firewall_type = $3,
				active = $4,
				updated_at = NOW()`,
			srv.UID, srv.Titular, req.FirewallType, req.Active, req.IP)
		
		if err != nil {
			log.Printf("[webhook-go] Erro ao inserir status do firewall: %v", err)
			http.Error(w, "Erro ao salvar status do firewall", http.StatusInternalServerError)
			return
		}
		
		// Retorna os dados do servidor como resposta
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(srv)
	})

	// Rota para receber regras do firewall
	http.HandleFunc("/firewall_rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		
		var req FirewallRuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("[webhook-go] Erro ao decodificar JSON: %v", err)
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		
		// Consulta whitelist na tabela servidores usando o campo 'ip' do JSON
		var srv Servidor
		query := `SELECT uid, titular, ip FROM mtm.servidores WHERE TRIM(LOWER(ip)) = TRIM(LOWER($1)) LIMIT 1`
		err := db.QueryRowContext(context.Background(), query, req.IP).Scan(&srv.UID, &srv.Titular, &srv.IP)
		if err != nil {
			log.Printf("[webhook-go] Erro ao buscar servidor com IP '%s': %v", req.IP, err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("servidor não encontrado"))
			return
		}
		
		// Insere ou atualiza a regra do firewall
		_, err = db.ExecContext(context.Background(),
			`INSERT INTO mtm.firewall_rules (
				titular, port, protocol, action, description, source, active, priority, firewall_type, servidor_ip
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (servidor_ip, port, protocol, action, firewall_type) 
			DO UPDATE SET 
				description = $5,
				source = $6,
				active = $7,
				priority = $8,
				updated_at = NOW()`,
			srv.Titular, req.Port, req.Protocol, req.Action, req.Description, req.Source, req.Active, req.Priority, req.FirewallType, req.IP)
		
		if err != nil {
			log.Printf("[webhook-go] Erro ao inserir regra do firewall: %v", err)
			http.Error(w, "Erro ao salvar regra do firewall", http.StatusInternalServerError)
			return
		}
		
		// Retorna os dados do servidor como resposta
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(srv)
	})

	// Rota para receber métricas de processos
	http.HandleFunc("/process_metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		
		var req ProcessMetricsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("[webhook-go] Erro ao decodificar JSON: %v", err)
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		
		// Determinar o IP do servidor com base no formato do JSON recebido
		var serverIP, hostname string
		if req.ServerInfo != nil {
			// Formato antigo com ServerInfo
			serverIP = req.ServerInfo.IP
			hostname = req.ServerInfo.Hostname
		} else {
			// Formato novo com server_ip e hostname no nível raiz
			serverIP = req.ServerIP
			hostname = req.Hostname
		}
		
		// Verificar se temos um IP válido
		if serverIP == "" {
			log.Printf("[webhook-go] IP do servidor não fornecido no JSON")
			http.Error(w, "IP do servidor não fornecido", http.StatusBadRequest)
			return
		}
		
		// Consulta whitelist na tabela servidores usando o campo 'ip' do JSON
		var srv Servidor
		query := `SELECT uid, titular, ip FROM mtm.servidores WHERE TRIM(LOWER(ip)) = TRIM(LOWER($1)) LIMIT 1`
		err := db.QueryRowContext(context.Background(), query, serverIP).Scan(&srv.UID, &srv.Titular, &srv.IP)
		if err != nil {
			log.Printf("[webhook-go] Erro ao buscar servidor com IP '%s': %v", serverIP, err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("servidor não encontrado"))
			return
		}
		
		// Determinar qual campo de processos usar (top_processes ou processes)
		var processesByCPU, processesByRAM []Process
		if req.Processes != nil {
			// Usar o campo "processes" se estiver presente
			processesByCPU = req.Processes.ByCPU
			processesByRAM = req.Processes.ByRAM
		} else {
			// Caso contrário, usar o campo "top_processes"
			processesByCPU = req.TopProcesses.ByCPU
			processesByRAM = req.TopProcesses.ByRAM
		}
		
		// Criar um objeto combinado com processos CPU e RAM
		processesMap := map[string]interface{}{
			"by_cpu": processesByCPU,
			"by_ram": processesByRAM,
		}
		
		// Converter o mapa combinado para JSONB
		processesJSON, err := json.Marshal(processesMap)
		if err != nil {
			log.Printf("[webhook-go] Erro ao serializar processos: %v", err)
			http.Error(w, "Erro ao processar dados", http.StatusInternalServerError)
			return
		}
		
		// Inserir uma única linha com todos os processos e métricas do sistema
		_, err = db.ExecContext(context.Background(),
			`INSERT INTO mtm.process_metrics (
				server_ip, hostname, process_source, processes, server_uid, titular,
				cpu_cores, cpu_total, cpu_usada, cpu_livre, mem_total, mem_usada, mem_livre,
				disco_total, disco_usado, disco_livre
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			serverIP, hostname, "combined", processesJSON, srv.UID, srv.Titular,
			req.SystemMetrics.CPUCores, req.SystemMetrics.CPUTotal, req.SystemMetrics.CPUUsada, req.SystemMetrics.CPULivre,
			req.SystemMetrics.MemTotal, req.SystemMetrics.MemUsada, req.SystemMetrics.MemLivre,
			req.SystemMetrics.DiscoTotal, req.SystemMetrics.DiscoUsado, req.SystemMetrics.DiscoLivre)
		
		if err != nil {
			log.Printf("[webhook-go] Erro ao inserir processos: %v", err)
			http.Error(w, "Erro ao salvar dados", http.StatusInternalServerError)
			return
		}
		
		// Retorna os dados do servidor como resposta
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(srv)
	})

	// Rota para receber e atualizar configurações do servidor
	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		
		var req ConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("[webhook-go] Erro ao decodificar JSON: %v", err)
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		
		// Verifica se o IP foi fornecido
		if req.IP == "" {
			log.Printf("[webhook-go] IP não fornecido no JSON")
			http.Error(w, "IP não fornecido", http.StatusBadRequest)
			return
		}
		
		// Consulta se o servidor com o IP existe na tabela servidores
		var srv Servidor
		query := `SELECT uid, titular, ip FROM mtm.servidores WHERE TRIM(LOWER(ip)) = TRIM(LOWER($1)) LIMIT 1`
		err := db.QueryRowContext(context.Background(), query, req.IP).Scan(&srv.UID, &srv.Titular, &srv.IP)
		if err != nil {
			log.Printf("[webhook-go] Erro ao buscar servidor com IP '%s': %v", req.IP, err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("servidor não encontrado"))
			return
		}
		
		// Constrói a query de atualização dinamicamente com base nos campos fornecidos
		updateQuery := "UPDATE mtm.servidores SET "
		updateParams := []interface{}{}
		paramCounter := 1
		
		// Adiciona campos à query apenas se estiverem presentes no JSON
		fields := make([]string, 0)
		
		if req.CPU > 0 {
			fields = append(fields, fmt.Sprintf("cpu = $%d", paramCounter))
			updateParams = append(updateParams, req.CPU)
			paramCounter++
		}
		
		if req.RAM > 0 {
			fields = append(fields, fmt.Sprintf("ram = $%d", paramCounter))
			updateParams = append(updateParams, req.RAM)
			paramCounter++
		}
		
		if req.Storage > 0 {
			fields = append(fields, fmt.Sprintf("storage = $%d", paramCounter))
			updateParams = append(updateParams, req.Storage)
			paramCounter++
		}
		
		if req.Sistema != "" {
			fields = append(fields, fmt.Sprintf("sistema = $%d", paramCounter))
			updateParams = append(updateParams, req.Sistema)
			paramCounter++
		}
		
		// Adiciona o campo papel diretamente sem normalização
		if req.Papel != "" {
			fields = append(fields, fmt.Sprintf("papel = $%d", paramCounter))
			updateParams = append(updateParams, req.Papel)
			paramCounter++
			log.Printf("[webhook-go] Campo 'papel' atualizado para '%s' no servidor com IP '%s'", req.Papel, req.IP)
		}
		
		// Se nenhum campo foi fornecido para atualização
		if len(fields) == 0 {
			log.Printf("[webhook-go] Nenhum campo válido fornecido para atualização")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("nenhum campo válido fornecido para atualização"))
			return
		}
		
		// Completa a query com os campos e a condição WHERE
		updateQuery += strings.Join(fields, ", ")
		updateQuery += fmt.Sprintf(" WHERE uid = $%d", paramCounter)
		updateParams = append(updateParams, srv.UID)
		
		// Executa a atualização
		_, err = db.ExecContext(context.Background(), updateQuery, updateParams...)
		if err != nil {
			log.Printf("[webhook-go] Erro ao atualizar configurações do servidor: %v", err)
			http.Error(w, "Erro ao atualizar configurações", http.StatusInternalServerError)
			return
		}
		
		log.Printf("[webhook-go] Configurações atualizadas com sucesso para o servidor %s", req.IP)
		
		// Retorna os dados do servidor como resposta
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(srv)
	})

	log.Println("[webhook-go] Servidor rodando na porta 8080...")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("[webhook-go] Erro ao iniciar servidor HTTP: %v", err)
	}
}
