package main

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"runtime/secret"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const adminHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Age Vault Admin</title>
    <style>
        body { font-family: sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f2f2f2; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"], textarea { width: 100%; padding: 8px; box-sizing: border-box; }
        button { padding: 10px 15px; background-color: #007bff; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background-color: #0056b3; }
        button.delete { background-color: #dc3545; }
        button.delete:hover { background-color: #c82333; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .masked { color: #888; font-family: monospace; letter-spacing: 2px; }
        .alert { padding: 15px; background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; border-radius: 4px; margin-bottom: 20px;}
        .lock-container { border: 1px solid #ddd; padding: 30px; border-radius: 8px; background-color: #f9f9f9; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Age-Encrypted Vault</h1>
        <div>
            {{if not .Locked}}
            <a href="/export" download="vault.age"><button>Export Backup (.age)</button></a>
            {{end}}
            <button onclick="location.reload()" style="background-color: #6c757d;">Refresh</button>
        </div>
    </div>

    {{if .Error}}
    <div class="alert">
        <strong>Error:</strong> {{.Error}}
    </div>
    {{end}}

    {{if .Locked}}
    <div class="lock-container">
        <h2>Vault is Locked </h2>
        <p>The Age Master Key was not provided at startup or could not be fetched from the Cloud KMS.</p>
        <p>Pods requesting secrets will remain in <code>ContainerCreating</code> state until unlocked.</p>
        
        <form action="/unlock" method="POST" style="margin-top: 20px; text-align: left;">
            <div class="form-group">
                <label>Enter Master Key (AGE-SECRET-KEY-1...)</label>
                <input type="password" name="master_key" required placeholder="Paste your age master key here">
            </div>
            <button type="submit" style="width: 100%;">Unlock Vault</button>
        </form>
    </div>
    {{else}}
    <h3>Existing Secrets (Values are blind-write only)</h3>
    <table>
        <thead>
            <tr>
                <th>Vault Path</th>
                <th>Value</th>
                <th>Allowed Namespaces</th>
                <th>Allowed Service Accounts</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {{range .Secrets}}
            <tr>
                <td><strong>{{.Path}}</strong></td>
                <td class="masked">********</td>
                <td>{{.Namespaces}}</td>
                <td>{{.ServiceAccounts}}</td>
                <td>
                    <form action="/delete" method="POST" style="margin:0;">
                        <input type="hidden" name="path" value="{{.Path}}">
                        <button type="submit" class="delete" onclick="return confirm('Delete this secret?');">Delete</button>
                    </form>
                </td>
            </tr>
            {{else}}
            <tr><td colspan="5">No secrets configured yet.</td></tr>
            {{end}}
        </tbody>
    </table>

    <hr style="margin: 40px 0;">

    <h3>Add / Update Secret</h3>
    <form action="/update" method="POST">
        <div class="form-group">
            <label>Secret Path</label>
            <input type="text" name="path" required placeholder="e.g., /db/postgres/password">
        </div>
        <div class="form-group">
            <label>Secret Value</label>
            <textarea name="value" rows="4" required placeholder="Will be securely encrypted. Cannot be read back from the UI."></textarea>
        </div>
        <div class="form-group">
            <label>Allowed Namespaces (comma-separated, use * for all)</label>
            <input type="text" name="namespaces" value="*">
        </div>
        <div class="form-group">
            <label>Allowed Service Accounts (comma-separated, use * for all)</label>
            <input type="text" name="service_accounts" value="*">
        </div>
        <button type="submit">Save Secret</button>
    </form>
    {{end}}
</body>
</html>
`

type UISecret struct {
	Path            string
	Namespaces      string
	ServiceAccounts string
}

type UIState struct {
	Locked  bool
	Error   string
	Secrets []UISecret
}

func startHTTPServer(ctx context.Context, logger *slog.Logger, cfg Config, manager *VaultManager) error {
	tmpl := template.Must(template.New("admin").Parse(adminHTML))
	mux := http.NewServeMux()

	// GET / - Renders the UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		state := UIState{
			Locked: manager.IsLocked(),
		}

		if !state.Locked {
			var loadErr error
			// Fetch the tree safely and strip values before it touches the template
			secret.Do(func() {
				tree, err := manager.LoadAndDecrypt(ctx)
				if err != nil {
					loadErr = err
					return
				}
				for path, node := range tree.Nodes {
					state.Secrets = append(state.Secrets, UISecret{
						Path:            path,
						Namespaces:      strings.Join(node.AllowedNamespaces, ", "),
						ServiceAccounts: strings.Join(node.AllowedServiceAccounts, ", "),
					})
				}
			})

			if loadErr != nil {
				state.Error = fmt.Sprintf("Failed to load vault: %v", loadErr)
			} else {
				// Sort secrets alphabetically for stable UI rendering
				sort.Slice(state.Secrets, func(i, j int) bool {
					return state.Secrets[i].Path < state.Secrets[j].Path
				})
			}
		}

		tmpl.Execute(w, state)
	})

	// POST /unlock - Manual Vault Unlock
	mux.HandleFunc("/unlock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		masterKey := r.FormValue("master_key")
		if err := manager.Unlock(masterKey); err != nil {
			logger.Warn("Failed unlock attempt", "error", err)
			state := UIState{Locked: true, Error: "Invalid Master Key provided."}
			tmpl.Execute(w, state)
			return
		}

		logger.Info("Vault successfully unlocked via UI")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// POST /update - Blind write an update via the form
	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || manager.IsLocked() {
			http.Error(w, "Method not allowed or Vault Locked", http.StatusMethodNotAllowed)
			return
		}

		path := strings.TrimSpace(r.FormValue("path"))
		value := r.FormValue("value")

		nsParts := strings.Split(r.FormValue("namespaces"), ",")
		var namespaces []string
		for _, ns := range nsParts {
			if trimmed := strings.TrimSpace(ns); trimmed != "" {
				namespaces = append(namespaces, trimmed)
			}
		}

		saParts := strings.Split(r.FormValue("service_accounts"), ",")
		var serviceAccounts []string
		for _, sa := range saParts {
			if trimmed := strings.TrimSpace(sa); trimmed != "" {
				serviceAccounts = append(serviceAccounts, trimmed)
			}
		}

		if path == "" || value == "" {
			http.Error(w, "Path and Value are required", http.StatusBadRequest)
			return
		}

		var updateErr error
		secret.Do(func() {
			tree, err := manager.LoadAndDecrypt(ctx)
			if err != nil {
				updateErr = err
				return
			}

			if tree.Nodes == nil {
				tree.Nodes = make(map[string]*VaultNode)
			}

			tree.Nodes[path] = &VaultNode{
				Value:                  value,
				AllowedNamespaces:      namespaces,
				AllowedServiceAccounts: serviceAccounts,
			}

			updateErr = manager.EncryptAndSave(ctx, tree)
		})

		if updateErr != nil {
			http.Error(w, fmt.Sprintf("Failed to save secret: %v", updateErr), http.StatusInternalServerError)
			return
		}

		logger.Info("Secret updated via UI", "path", path)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// POST /delete - Deletes a specific secret
	mux.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || manager.IsLocked() {
			http.Error(w, "Method not allowed or Vault Locked", http.StatusMethodNotAllowed)
			return
		}

		path := r.FormValue("path")
		var deleteErr error

		secret.Do(func() {
			tree, err := manager.LoadAndDecrypt(ctx)
			if err != nil {
				deleteErr = err
				return
			}
			if tree.Nodes != nil {
				delete(tree.Nodes, path)
				deleteErr = manager.EncryptAndSave(ctx, tree)
			}
		})

		if deleteErr != nil {
			http.Error(w, fmt.Sprintf("Failed to delete secret: %v", deleteErr), http.StatusInternalServerError)
			return
		}

		logger.Info("Secret deleted via UI", "path", path)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// GET /export - Download full encrypted Age blob
	mux.HandleFunc("/export", func(w http.ResponseWriter, r *http.Request) {
		if manager.IsLocked() {
			http.Error(w, "Vault Locked", http.StatusForbidden)
			return
		}

		sec, err := manager.k8sClient.CoreV1().Secrets(cfg.VaultNamespace).Get(ctx, cfg.VaultSecretName, metav1.GetOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="vault.age"`)
		w.Write(sec.Data["vault.enc"])
	})

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	server := &http.Server{Addr: addr, Handler: mux}
	logger.Info("HTTP Admin UI listening", "address", addr)

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	return server.ListenAndServe()
}
