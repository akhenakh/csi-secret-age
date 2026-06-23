package main

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"path"
	"runtime/secret"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type contextKey string

const userPermsKey contextKey = "userPerms"

func getUserPerms(r *http.Request) *UserPermissions {
	if v := r.Context().Value(userPermsKey); v != nil {
		if up, ok := v.(*UserPermissions); ok {
			return up
		}
	}
	return nil
}

func withAuth(handler http.Handler, permMgr *PermissionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if permMgr == nil {
			handler.ServeHTTP(w, r)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		username, err := permMgr.ValidateJWT(token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userPerms := permMgr.GetUserPermissions(username)
		ctx := context.WithValue(r.Context(), userPermsKey, userPerms)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

const adminHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>CSI Secret Age Admin</title>
    <style>
        body { font-family: sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
        a { text-decoration: none; color: #007bff; }
        a:hover { text-decoration: underline; }
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
        button.secondary { background-color: #6c757d; }
        button.secondary:hover { background-color: #545b62; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .masked { color: #888; font-family: monospace; letter-spacing: 2px; }
        .alert { padding: 15px; background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; border-radius: 4px; margin-bottom: 20px;}
        .lock-container { border: 1px solid #ddd; padding: 30px; border-radius: 8px; background-color: #f9f9f9; text-align: center; }
        .breadcrumb { margin-bottom: 20px; font-size: 14px; }
        .breadcrumb a { color: #007bff; }
        .breadcrumb span { color: #666; margin: 0 5px; }
        .tree-list { list-style: none; padding: 0; margin: 0; }
        .tree-item { padding: 10px; border: 1px solid #ddd; margin-bottom: 5px; border-radius: 4px; display: flex; align-items: center; justify-content: space-between; }
        .tree-item:hover { background-color: #f8f9fa; }
        .tree-item.folder { background-color: #e9ecef; }
        .tree-item.folder:hover { background-color: #dee2e6; }
        .tree-icon { margin-right: 10px; font-size: 18px; }
        .tree-name { font-weight: 500; flex: 1; }
        .entry-meta { color: #666; font-size: 12px; }
        .detail-box { border: 1px solid #ddd; padding: 20px; border-radius: 8px; background-color: #f9f9f9; }
        .detail-row { margin-bottom: 15px; }
        .detail-label { font-weight: bold; color: #555; margin-bottom: 5px; }
        .detail-value { font-family: monospace; background: #fff; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .folder-badge { display: inline-block; background: #e9ecef; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-left: 8px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Age-Encrypted Vault</h1>
        <div>
            {{if not .Locked}}
            <a href="/export" download="vault.age"><button>Export Backup (.age)</button></a>
            {{end}}
            <button onclick="location.reload()" class="secondary">Refresh</button>
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
        {{if .IsEntryView}}
            <div class="breadcrumb">
                <a href="/">root</a>
                {{range .Breadcrumbs}}
                    <span>/</span>
                    {{if .IsLast}}
                        <span>{{.Name}}</span>
                    {{else}}
                        <a href="/?path={{.Path}}">{{.Name}}</a>
                    {{end}}
                {{end}}
            </div>
            <a href="/?path={{.ParentPath}}"><button class="secondary">&larr; Back to folder</button></a>
            <h2>Entry: {{.EntryPath}}</h2>
            <div class="detail-box">
                <div class="detail-row">
                    <div class="detail-label">Vault Path</div>
                    <div class="detail-value">{{.EntryPath}}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Value</div>
                    <div class="detail-value masked">********</div>
                </div>
                <div style="margin-top: 20px;">
                    <form action="/delete" method="POST" style="display: inline;" onsubmit="return confirm('Delete this secret?');">
                        <input type="hidden" name="path" value="{{.EntryPath}}">
                        <button type="submit" class="delete">Delete Secret</button>
                    </form>
                </div>
            </div>
        {{else}}
            <div class="breadcrumb">
                <a href="/">root</a>
                {{range .Breadcrumbs}}
                    <span>/</span>
                    {{if .IsLast}}
                        <span>{{.Name}}</span>
                    {{else}}
                        <a href="/?path={{.Path}}">{{.Name}}</a>
                    {{end}}
                {{end}}
            </div>
            <h3>Contents of {{if .CurrentPath}}{{.CurrentPath}}{{else}}root{{end}}</h3>

            {{if .Folder}}
            <div class="detail-box" style="margin-bottom: 20px;">
                <div class="detail-row">
                    <div class="detail-label">Folder Info</div>
                    <div class="detail-value">Path: {{.Folder.Path}}</div>
                </div>
                <div style="margin-top: 10px;">
                    <form action="/delete" method="POST" style="display: inline;" onsubmit="return confirm('Delete this folder?');">
                        <input type="hidden" name="path" value="{{.CurrentPath}}">
                        <button type="submit" class="delete">Delete Folder</button>
                    </form>
                </div>
            </div>
            {{end}}

            <ul class="tree-list">
                {{range .Folders}}
                <li class="tree-item folder">
                    <a href="/?path={{.Path}}" class="tree-name">
                        <span class="tree-icon">&#128193;</span>{{.Name}}
                    </a>
                </li>
                {{end}}
                {{range .Entries}}
                <li class="tree-item">
                    <a href="/entry?path={{.Path}}" class="tree-name">
                        <span class="tree-icon">&#128196;</span>{{.Name}}
                    </a>
                </li>
                {{end}}
                {{if and (not .Folders) (not .Entries) (not .Folder)}}
                <li class="tree-item">No items in this folder.</li>
                {{end}}
            </ul>
        {{end}}

    <hr style="margin: 40px 0;">

    <h3>Add / Update</h3>
    <form action="/update" method="POST">
        <div class="form-group">
            <label>Path</label>
            <input type="text" name="path" required placeholder="e.g., /db/postgres/password">
        </div>
        <div class="form-group">
            <label>
                <input type="checkbox" name="is_folder" value="true">
                Create as folder (no secret value, acts as a namespace grouping only)
            </label>
        </div>
        <div class="form-group" id="value-group">
            <label>Secret Value</label>
            <textarea name="value" rows="4" placeholder="Will be securely encrypted. Cannot be read back from the UI."></textarea>
        </div>
        <button type="submit">Save</button>
    </form>
    <script>
        document.querySelector('input[name="is_folder"]').addEventListener('change', function() {
            var group = document.getElementById('value-group');
            if (this.checked) {
                group.style.display = 'none';
                group.querySelector('textarea').removeAttribute('required');
            } else {
                group.style.display = 'block';
                group.querySelector('textarea').setAttribute('required', 'required');
            }
        });
    </script>
    {{end}}
</body>
</html>
`

type UISecret struct {
	Path string
	Name string
}

type UIFolder struct {
	Name string
	Path string
}

type UIFolderDetail struct {
	Path string
}

type Breadcrumb struct {
	Name   string
	Path   string
	IsLast bool
}

type UIState struct {
	Locked      bool
	Error       string
	IsEntryView bool

	CurrentPath string
	CurrentName string
	ParentPath  string

	Folders     []UIFolder
	Entries     []UISecret
	Folder      *UIFolderDetail
	Breadcrumbs []Breadcrumb

	EntryPath string
	Entry     UISecret
}

func normalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// checkPathConflict validates that a new path does not conflict with existing nodes.
// Returns an error message if there is a conflict, empty string otherwise.
func checkPathConflict(tree *VaultTree, newPath string, isFolder bool) string {
	newPath = normalizePath(newPath)

	// 1. If the exact path already exists with a different type, reject.
	if existing, ok := tree.Nodes[newPath]; ok && existing.IsFolder != isFolder {
		if existing.IsFolder {
			return fmt.Sprintf("path %s already exists as a folder", newPath)
		}
		return fmt.Sprintf("path %s already exists as a secret", newPath)
	}

	// 2. If creating a leaf, it cannot have existing children.
	if !isFolder {
		prefix := newPath
		if prefix != "/" {
			prefix = prefix + "/"
		}
		for vaultPath := range tree.Nodes {
			if vaultPath != newPath && strings.HasPrefix(vaultPath, prefix) {
				return fmt.Sprintf("secret %s cannot have children because a path %s already exists under it", newPath, vaultPath)
			}
		}
	}

	// 3. If creating a leaf or a folder, it cannot be placed under an existing leaf.
	for vaultPath, node := range tree.Nodes {
		if vaultPath == newPath {
			continue
		}
		if node.IsFolder {
			continue
		}
		prefix := vaultPath
		if prefix != "/" {
			prefix = prefix + "/"
		}
		if strings.HasPrefix(newPath, prefix) {
			return fmt.Sprintf("cannot create %s under existing secret %s", newPath, vaultPath)
		}
	}

	return ""
}

func buildTreeState(tree *VaultTree, currentPath string, entryPath string, userPerms *UserPermissions) UIState {
	currentPath = normalizePath(currentPath)
	entryPath = normalizePath(entryPath)

	state := UIState{
		CurrentPath: currentPath,
		IsEntryView: entryPath != "/",
	}

	if state.IsEntryView {
		state.EntryPath = entryPath
		if node, ok := tree.Nodes[entryPath]; ok && !node.IsFolder {
			if userPerms == nil || userPerms.CanRead(entryPath) {
				state.Entry = UISecret{
					Path: entryPath,
					Name: path.Base(entryPath),
				}
			}
		}
		state.ParentPath = path.Dir(entryPath)
		if state.ParentPath == "." {
			state.ParentPath = "/"
		}
	} else {
		state.CurrentName = path.Base(currentPath)
		if currentPath == "/" || currentPath == "" {
			state.CurrentPath = "/"
			state.CurrentName = ""
		}
		state.ParentPath = path.Dir(currentPath)
		if state.ParentPath == "." {
			state.ParentPath = "/"
		}
	}

	// Build breadcrumbs
	if currentPath != "" && currentPath != "/" {
		parts := strings.Split(strings.Trim(currentPath, "/"), "/")
		buildPath := "/"
		for i, part := range parts {
			buildPath = path.Join(buildPath, part)
			if buildPath == "." {
				buildPath = "/"
			}
			state.Breadcrumbs = append(state.Breadcrumbs, Breadcrumb{
				Name:   part,
				Path:   buildPath,
				IsLast: i == len(parts)-1,
			})
		}
	}

	if state.IsEntryView {
		// For entry view, breadcrumbs include the entry path
		state.Breadcrumbs = nil
		parts := strings.Split(strings.Trim(entryPath, "/"), "/")
		buildPath := "/"
		for i, part := range parts {
			buildPath = path.Join(buildPath, part)
			if buildPath == "." {
				buildPath = "/"
			}
			state.Breadcrumbs = append(state.Breadcrumbs, Breadcrumb{
				Name:   part,
				Path:   buildPath,
				IsLast: i == len(parts)-1,
			})
		}
		return state
	}

	// Check if current path itself is a folder node
	if node, ok := tree.Nodes[currentPath]; ok && node.IsFolder {
		if userPerms == nil || userPerms.CanRead(currentPath) {
			state.Folder = &UIFolderDetail{
				Path: currentPath,
			}
		}
	}

	// Build folders and entries for current path
	folderSet := make(map[string]bool)
	prefix := currentPath
	if prefix != "/" && prefix != "" {
		prefix = prefix + "/"
	}

	for vaultPath, node := range tree.Nodes {
		if vaultPath == currentPath {
			continue // handled above
		}
		if !strings.HasPrefix(vaultPath, prefix) {
			continue
		}
		if userPerms != nil && !userPerms.CanRead(vaultPath) {
			continue
		}
		remaining := strings.TrimPrefix(vaultPath, prefix)
		if remaining == "" {
			continue
		}
		segments := strings.SplitN(remaining, "/", 2)
		name := segments[0]
		if len(segments) == 1 && !node.IsFolder {
			// It's a leaf entry
			state.Entries = append(state.Entries, UISecret{
				Path: vaultPath,
				Name: name,
			})
		} else {
			// It's a folder (either has more segments, or is explicitly a folder node)
			folderPath := path.Join(currentPath, name)
			if currentPath == "/" || currentPath == "" {
				folderPath = "/" + name
			}
			folderSet[folderPath] = true
		}
	}

	for folderPath := range folderSet {
		state.Folders = append(state.Folders, UIFolder{
			Name: path.Base(folderPath),
			Path: folderPath,
		})
	}

	sort.Slice(state.Folders, func(i, j int) bool {
		return state.Folders[i].Name < state.Folders[j].Name
	})
	sort.Slice(state.Entries, func(i, j int) bool {
		return state.Entries[i].Name < state.Entries[j].Name
	})

	return state
}

func startHTTPServer(ctx context.Context, logger *slog.Logger, cfg Config, manager *VaultManager, permMgr *PermissionManager) error {
	tmpl := template.Must(template.New("admin").Parse(adminHTML))
	mux := http.NewServeMux()

	// GET / - Renders the tree UI
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
			secret.Do(func() {
				tree, err := manager.LoadAndDecrypt(ctx)
				if err != nil {
					loadErr = err
					return
				}
				currentPath := r.URL.Query().Get("path")
				if currentPath == "" {
					currentPath = "/"
				}
				userPerms := getUserPerms(r)
				state = buildTreeState(tree, currentPath, "", userPerms)
				state.Locked = false
			})

			if loadErr != nil {
				state.Error = fmt.Sprintf("Failed to load vault: %v", loadErr)
			}
		}

		tmpl.Execute(w, state)
	})

	// GET /entry - Shows entry details
	mux.HandleFunc("/entry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		state := UIState{
			Locked: manager.IsLocked(),
		}

		if !state.Locked {
			var loadErr error
			secret.Do(func() {
				tree, err := manager.LoadAndDecrypt(ctx)
				if err != nil {
					loadErr = err
					return
				}
				entryPath := r.URL.Query().Get("path")
				userPerms := getUserPerms(r)
				if userPerms != nil && !userPerms.CanRead(entryPath) {
					loadErr = fmt.Errorf("access denied to path %s", entryPath)
					return
				}
				state = buildTreeState(tree, "", entryPath, userPerms)
				state.Locked = false
			})

			if loadErr != nil {
				state.Error = fmt.Sprintf("Failed to load vault: %v", loadErr)
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
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		var unlockErr error
		secret.Do(func() {
			masterKey := r.FormValue("master_key")
			unlockErr = manager.Unlock(masterKey)
		})
		if unlockErr != nil {
			logger.Warn("Failed unlock attempt", "error", unlockErr)
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
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		userPerms := getUserPerms(r)

		var updateErr error
		var updatePath string
		var isFolder bool
		secret.Do(func() {
			updatePath = strings.TrimSpace(r.FormValue("path"))
			isFolder = r.FormValue("is_folder") == "true"
			value := r.FormValue("value")

			if updatePath == "" {
				updateErr = fmt.Errorf("path is required")
				return
			}
			if !isFolder && value == "" {
				updateErr = fmt.Errorf("value is required for secrets")
				return
			}

			if userPerms != nil && !userPerms.CanWrite(updatePath) {
				updateErr = fmt.Errorf("forbidden")
				return
			}

			updateErr = manager.UpdateVault(ctx, func(tree *VaultTree) error {
				if tree.Nodes == nil {
					tree.Nodes = make(map[string]*VaultNode)
				}

				if conflict := checkPathConflict(tree, updatePath, isFolder); conflict != "" {
					return fmt.Errorf("conflict: %s", conflict)
				}

				tree.Nodes[updatePath] = &VaultNode{
					Value:    value,
					IsFolder: isFolder,
				}
				return nil
			})
		})

		if updateErr != nil {
			http.Error(w, fmt.Sprintf("Failed to save: %v", updateErr), http.StatusInternalServerError)
			return
		}

		logger.Info("Updated via UI", "path", updatePath, "is_folder", isFolder)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// POST /delete - Deletes a specific secret or folder
	mux.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || manager.IsLocked() {
			http.Error(w, "Method not allowed or Vault Locked", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		deletePath := r.FormValue("path")
		userPerms := getUserPerms(r)
		if userPerms != nil && !userPerms.CanWrite(deletePath) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		var deleteErr error

		secret.Do(func() {
			deleteErr = manager.UpdateVault(ctx, func(tree *VaultTree) error {
				if tree.Nodes != nil {
					delete(tree.Nodes, deletePath)
				}
				return nil
			})
		})

		if deleteErr != nil {
			http.Error(w, fmt.Sprintf("Failed to delete: %v", deleteErr), http.StatusInternalServerError)
			return
		}

		logger.Info("Deleted via UI", "path", deletePath)
		// Redirect to parent folder so the tree stays visible
		parentDir := path.Dir(deletePath)
		if parentDir == "." {
			parentDir = "/"
		}
		http.Redirect(w, r, "/?path="+parentDir, http.StatusSeeOther)
	})

	// GET /export - Download full encrypted Age blob
	mux.HandleFunc("/export", func(w http.ResponseWriter, r *http.Request) {
		if manager.IsLocked() {
			http.Error(w, "Vault Locked", http.StatusForbidden)
			return
		}

		userPerms := getUserPerms(r)
		if userPerms != nil && !userPerms.CanExport() {
			http.Error(w, "Forbidden", http.StatusForbidden)
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
	server := &http.Server{
		Addr:         addr,
		Handler:      withAuth(mux, permMgr),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	logger.Info("HTTP Admin UI listening", "address", addr)

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	return server.ListenAndServe()
}
