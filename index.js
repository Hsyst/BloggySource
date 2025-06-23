const express = require("express");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");

// Configurações iniciais
const config = {
  port: 3000,
  sessionSecret: "sua_chave_secreta_forte_aqui_" + uuidv4(), // Em produção, use uma chave fixa e segura
  saltRounds: 12,
  adminUsername: "admin",
  adminEmail: "admin@bloggysource.hsyst.xyz",
  // Configurações de rate limiting
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // limite cada IP para 100 requisições por janela
  },
  // Configurações de CSRF
  csrf: {
    cookie: true,
  },
};

// Inicialização do app Express
const app = express();

// Configuração de middlewares de segurança
// Add CSP headers
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
      styleSrc: [
        "'self'",
        "https://cdn.tailwindcss.com",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com",
        "https://ui-avatars.com",
        "'unsafe-inline'",
      ],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
    },
  }),
);
app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuração de rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
});
app.use(limiter);

// Configuração de sessão
app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.db",
      dir: "./db",
    }),
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Em produção, defina como true se estiver usando HTTPS
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 dia
    },
  }),
);

// Configuração de CSRF
const csrfProtection = csrf(config.csrf);
app.use(csrfProtection);

// Servir arquivos estáticos
app.use(express.static(path.join(__dirname, "public")));

// Inicialização do banco de dados SQLite
const dbPath = "./db/bloggysource.db";
const dbDir = path.dirname(dbPath);

// Garantir que o diretório do banco de dados existe
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(
  dbPath,
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) {
      console.error("Erro ao conectar ao banco de dados:", err.message);
    } else {
      console.log("Conectado ao banco de dados SQLite");
      initializeDatabase();
    }
  },
);

// Inicialização do banco de dados
function initializeDatabase() {
  db.serialize(() => {
    // Tabela de usuários
    db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

    // Tabela de posts
    db.run(`CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            description TEXT,
            image_url TEXT,
            views INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

    // Tabela de categorias
    db.run(`CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )`);

    // Tabela de relacionamento post-categoria
    db.run(`CREATE TABLE IF NOT EXISTS post_categories (
            post_id INTEGER NOT NULL,
            category_id INTEGER NOT NULL,
            PRIMARY KEY (post_id, category_id),
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (category_id) REFERENCES categories (id)
        )`);

    // Tabela de comentários
    db.run(`CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            is_approved BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

    // Tabela de moderação
    db.run(`CREATE TABLE IF NOT EXISTS moderations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            moderator_id INTEGER NOT NULL,
            post_id INTEGER,
            comment_id INTEGER,
            action TEXT NOT NULL,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (moderator_id) REFERENCES users (id),
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (comment_id) REFERENCES comments (id)
        )`);

    // Criar usuário admin se não existir
    db.get(
      "SELECT id FROM users WHERE username = ?",
      [config.adminUsername],
      (err, row) => {
        if (err) {
          console.error("Erro ao verificar usuário admin:", err);
          return;
        }

        if (!row) {
          //const adminPassword = uuidv4(); // Senha aleatória para o admin
          const adminPassword = "12345678@#admin";
          bcrypt.hash(adminPassword, config.saltRounds, (err, hash) => {
            if (err) {
              console.error("Erro ao criar hash da senha do admin:", err);
              return;
            }

            db.run(
              "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, TRUE)",
              [config.adminUsername, config.adminEmail, hash],
              function (err) {
                if (err) {
                  console.error("Erro ao criar usuário admin:", err);
                } else {
                  console.log(
                    `Usuário admin criado com sucesso. Credenciais:\nUsername: ${config.adminUsername}\nPassword: ${adminPassword}`,
                  );
                }
              },
            );
          });
        }
      },
    );
  });
}

// Middleware para verificar autenticação
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Não autorizado" });
  }
  next();
}

// Middleware para verificar se é admin
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) {
    return res.status(403).json({ error: "Acesso negado" });
  }
  next();
}

// Rota para servir o frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Rota para obter token CSRF
app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Rotas de autenticação
app.post("/api/register", async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  // Validações básicas
  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: "As senhas não coincidem" });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ error: "A senha deve ter pelo menos 8 caracteres" });
  }

  try {
    // Verificar se usuário ou email já existem
    const existingUser = await new Promise((resolve, reject) => {
      db.get(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        [username, email],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        },
      );
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Nome de usuário ou email já em uso" });
    }

    // Hash da senha
    const hashedPassword = await bcrypt.hash(password, config.saltRounds);

    // Criar usuário
    const result = await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        [username, email, hashedPassword],
        function (err) {
          if (err) reject(err);
          else resolve(this);
        },
      );
    });

    // Iniciar sessão
    req.session.userId = result.lastID;
    req.session.username = username;
    req.session.isAdmin = false;

    res.status(201).json({
      message: "Registro bem-sucedido",
      user: { id: result.lastID, username, email },
    });
  } catch (err) {
    console.error("Erro no registro:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Nome de usuário e senha são obrigatórios" });
  }

  try {
    // Buscar usuário
    const user = await new Promise((resolve, reject) => {
      db.get(
        "SELECT id, username, email, password_hash, is_admin FROM users WHERE username = ?",
        [username],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        },
      );
    });

    if (!user) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Verificar senha
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Iniciar sessão
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = user.is_admin;

    res.json({
      message: "Login bem-sucedido",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.is_admin,
      },
    });
  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Erro ao fazer logout:", err);
      return res.status(500).json({ error: "Erro ao fazer logout" });
    }
    res.clearCookie("connect.sid");
    res.json({ message: "Logout bem-sucedido" });
  });
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Não autenticado" });
  }

  res.json({
    user: {
      id: req.session.userId,
      username: req.session.username,
      isAdmin: req.session.isAdmin,
    },
  });
});

// Rotas de posts
app.get("/api/posts", async (req, res) => {
  try {
    const posts = await new Promise((resolve, reject) => {
      db.all(
        `SELECT p.id, p.title, p.description, p.image_url, p.views, p.created_at,
                 u.username as author,
                 GROUP_CONCAT(c.name) as categories
                 FROM posts p
                 JOIN users u ON p.user_id = u.id
                 LEFT JOIN post_categories pc ON p.id = pc.post_id
                 LEFT JOIN categories c ON pc.category_id = c.id
                 GROUP BY p.id
                 ORDER BY p.created_at DESC`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        },
      );
    });

    // Transformar string de categorias em array
    const formattedPosts = posts.map((post) => ({
      ...post,
      categories: post.categories ? post.categories.split(",") : [],
    }));

    res.json(formattedPosts);
  } catch (err) {
    console.error("Erro ao buscar posts:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.get("/api/posts/:id", async (req, res) => {
  const postId = req.params.id;

  try {
    // Buscar post
    const post = await new Promise((resolve, reject) => {
      db.get(
        `SELECT p.*, u.username as author
                 FROM posts p
                 JOIN users u ON p.user_id = u.id
                 WHERE p.id = ?`,
        [postId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        },
      );
    });

    if (!post) {
      return res.status(404).json({ error: "Post não encontrado" });
    }

    // Buscar categorias do post
    const categories = await new Promise((resolve, reject) => {
      db.all(
        `SELECT c.id, c.name
                 FROM post_categories pc
                 JOIN categories c ON pc.category_id = c.id
                 WHERE pc.post_id = ?`,
        [postId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        },
      );
    });

    // Buscar comentários aprovados
    const comments = await new Promise((resolve, reject) => {
      db.all(
        `SELECT c.id, c.content, c.created_at, u.username as author
                 FROM comments c
                 JOIN users u ON c.user_id = u.id
                 WHERE c.post_id = ? AND c.is_approved = TRUE
                 ORDER BY c.created_at DESC`,
        [postId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        },
      );
    });

    // Incrementar visualizações
    db.run("UPDATE posts SET views = views + 1 WHERE id = ?", [postId]);

    res.json({
      ...post,
      categories,
      comments,
    });
  } catch (err) {
    console.error("Erro ao buscar post:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/posts", requireAuth, async (req, res) => {
  const { title, content, description, image_url, categories } = req.body;
  const userId = req.session.userId;

  if (!title || !content) {
    return res
      .status(400)
      .json({ error: "Título e conteúdo são obrigatórios" });
  }

  try {
    // Inserir post
    const result = await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO posts (user_id, title, content, description, image_url) VALUES (?, ?, ?, ?, ?)",
        [userId, title, content, description || null, image_url || null],
        function (err) {
          if (err) reject(err);
          else resolve(this);
        },
      );
    });

    const postId = result.lastID;

    // Processar categorias
    if (categories && categories.length > 0) {
      // Verificar e criar categorias que não existem
      for (const categoryName of categories) {
        // Verificar se a categoria existe
        let category = await new Promise((resolve, reject) => {
          db.get(
            "SELECT id FROM categories WHERE name = ?",
            [categoryName],
            (err, row) => {
              if (err) reject(err);
              else resolve(row);
            },
          );
        });

        // Se não existir, criar
        if (!category) {
          const insertResult = await new Promise((resolve, reject) => {
            db.run(
              "INSERT INTO categories (name) VALUES (?)",
              [categoryName],
              function (err) {
                if (err) reject(err);
                else resolve(this);
              },
            );
          });

          category = { id: insertResult.lastID };
        }

        // Associar categoria ao post
        await new Promise((resolve, reject) => {
          db.run(
            "INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)",
            [postId, category.id],
            (err) => {
              if (err) reject(err);
              else resolve();
            },
          );
        });
      }
    }

    res.status(201).json({
      message: "Post criado com sucesso",
      postId,
    });
  } catch (err) {
    console.error("Erro ao criar post:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.put("/api/posts/:id", requireAuth, async (req, res) => {
  const postId = req.params.id;
  const { title, content, description, image_url, categories } = req.body;
  const userId = req.session.userId;

  if (!title || !content) {
    return res
      .status(400)
      .json({ error: "Título e conteúdo são obrigatórios" });
  }

  try {
    // Verificar se o post existe e pertence ao usuário (ou usuário é admin)
    const post = await new Promise((resolve, reject) => {
      db.get("SELECT user_id FROM posts WHERE id = ?", [postId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!post) {
      return res.status(404).json({ error: "Post não encontrado" });
    }

    if (post.user_id !== userId && !req.session.isAdmin) {
      return res
        .status(403)
        .json({ error: "Você não tem permissão para editar este post" });
    }

    // Atualizar post
    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE posts
                 SET title = ?, content = ?, description = ?, image_url = ?, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?`,
        [title, content, description || null, image_url || null, postId],
        (err) => {
          if (err) reject(err);
          else resolve();
        },
      );
    });

    // Atualizar categorias
    // Primeiro, remover todas as categorias atuais
    await new Promise((resolve, reject) => {
      db.run(
        "DELETE FROM post_categories WHERE post_id = ?",
        [postId],
        (err) => {
          if (err) reject(err);
          else resolve();
        },
      );
    });

    // Depois, adicionar as novas categorias (se houver)
    if (categories && categories.length > 0) {
      for (const categoryName of categories) {
        // Verificar se a categoria existe
        let category = await new Promise((resolve, reject) => {
          db.get(
            "SELECT id FROM categories WHERE name = ?",
            [categoryName],
            (err, row) => {
              if (err) reject(err);
              else resolve(row);
            },
          );
        });

        // Se não existir, criar
        if (!category) {
          const insertResult = await new Promise((resolve, reject) => {
            db.run(
              "INSERT INTO categories (name) VALUES (?)",
              [categoryName],
              function (err) {
                if (err) reject(err);
                else resolve(this);
              },
            );
          });

          category = { id: insertResult.lastID };
        }

        // Associar categoria ao post
        await new Promise((resolve, reject) => {
          db.run(
            "INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)",
            [postId, category.id],
            (err) => {
              if (err) reject(err);
              else resolve();
            },
          );
        });
      }
    }

    res.json({ message: "Post atualizado com sucesso" });
  } catch (err) {
    console.error("Erro ao atualizar post:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  const postId = req.params.id;
  const userId = req.session.userId;
  const isAdmin = req.session.isAdmin;

  try {
    // Verificar se o post existe
    const post = await new Promise((resolve, reject) => {
      db.get("SELECT user_id FROM posts WHERE id = ?", [postId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!post) {
      return res.status(404).json({ error: "Post não encontrado" });
    }

    // Verificar permissões (autor ou admin)
    if (post.user_id !== userId && !isAdmin) {
      return res
        .status(403)
        .json({ error: "Você não tem permissão para excluir este post" });
    }

    // Registrar ação de moderação se for admin
    if (isAdmin && post.user_id !== userId) {
      await new Promise((resolve, reject) => {
        db.run(
          "INSERT INTO moderations (moderator_id, post_id, action, reason) VALUES (?, ?, ?, ?)",
          [userId, postId, "delete", "Moderação administrativa"],
          (err) => {
            if (err) reject(err);
            else resolve();
          },
        );
      });
    }

    // Excluir post (o SQLite configurado com ON DELETE CASCADE cuidará das dependências)
    await new Promise((resolve, reject) => {
      db.run("DELETE FROM posts WHERE id = ?", [postId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    res.json({ message: "Post excluído com sucesso" });
  } catch (err) {
    console.error("Erro ao excluir post:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rotas de comentários
app.post("/api/posts/:id/comments", requireAuth, async (req, res) => {
  const postId = req.params.id;
  const { content } = req.body;
  const userId = req.session.userId;

  if (!content) {
    return res
      .status(400)
      .json({ error: "Conteúdo do comentário é obrigatório" });
  }

  try {
    // Verificar se o post existe
    const postExists = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM posts WHERE id = ?", [postId], (err, row) => {
        if (err) reject(err);
        else resolve(!!row);
      });
    });

    if (!postExists) {
      return res.status(404).json({ error: "Post não encontrado" });
    }

    // Inserir comentário
    const isApproved = req.session.isAdmin; // Comentários de admins são aprovados automaticamente

    const result = await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO comments (post_id, user_id, content, is_approved) VALUES (?, ?, ?, ?)",
        [postId, userId, content, isApproved],
        function (err) {
          if (err) reject(err);
          else resolve(this);
        },
      );
    });

    res.status(201).json({
      message: isApproved
        ? "Comentário adicionado"
        : "Comentário enviado para moderação",
      commentId: result.lastID,
      isApproved,
    });
  } catch (err) {
    console.error("Erro ao adicionar comentário:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rotas de moderação (apenas para admins)
app.get("/api/moderation/comments", requireAdmin, async (req, res) => {
  try {
    const comments = await new Promise((resolve, reject) => {
      db.all(
        `SELECT c.id, c.content, c.created_at, c.is_approved,
                 u.username as author, p.title as post_title, p.id as post_id
                 FROM comments c
                 JOIN users u ON c.user_id = u.id
                 JOIN posts p ON c.post_id = p.id
                 WHERE c.is_approved = FALSE
                 ORDER BY c.created_at DESC`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        },
      );
    });

    res.json(comments);
  } catch (err) {
    console.error("Erro ao buscar comentários para moderação:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post(
  "/api/moderation/comments/:id/approve",
  requireAdmin,
  async (req, res) => {
    const commentId = req.params.id;
    const moderatorId = req.session.userId;

    try {
      // Verificar se o comentário existe
      const comment = await new Promise((resolve, reject) => {
        db.get(
          "SELECT id, is_approved FROM comments WHERE id = ?",
          [commentId],
          (err, row) => {
            if (err) reject(err);
            else resolve(row);
          },
        );
      });

      if (!comment) {
        return res.status(404).json({ error: "Comentário não encontrado" });
      }

      if (comment.is_approved) {
        return res.status(400).json({ error: "Comentário já está aprovado" });
      }

      // Aprovar comentário
      await new Promise((resolve, reject) => {
        db.run(
          "UPDATE comments SET is_approved = TRUE WHERE id = ?",
          [commentId],
          (err) => {
            if (err) reject(err);
            else resolve();
          },
        );
      });

      // Registrar ação de moderação
      await new Promise((resolve, reject) => {
        db.run(
          "INSERT INTO moderations (moderator_id, comment_id, action) VALUES (?, ?, ?)",
          [moderatorId, commentId, "approve"],
          (err) => {
            if (err) reject(err);
            else resolve();
          },
        );
      });

      res.json({ message: "Comentário aprovado com sucesso" });
    } catch (err) {
      console.error("Erro ao aprovar comentário:", err);
      res.status(500).json({ error: "Erro interno do servidor" });
    }
  },
);

app.post(
  "/api/moderation/comments/:id/reject",
  requireAdmin,
  async (req, res) => {
    const commentId = req.params.id;
    const { reason } = req.body;
    const moderatorId = req.session.userId;

    try {
      // Verificar se o comentário existe
      const comment = await new Promise((resolve, reject) => {
        db.get(
          "SELECT id FROM comments WHERE id = ?",
          [commentId],
          (err, row) => {
            if (err) reject(err);
            else resolve(row);
          },
        );
      });

      if (!comment) {
        return res.status(404).json({ error: "Comentário não encontrado" });
      }

      // Registrar ação de moderação
      await new Promise((resolve, reject) => {
        db.run(
          "INSERT INTO moderations (moderator_id, comment_id, action, reason) VALUES (?, ?, ?, ?)",
          [
            moderatorId,
            commentId,
            "reject",
            reason || "Comentário rejeitado por moderação",
          ],
          (err) => {
            if (err) reject(err);
            else resolve();
          },
        );
      });

      // Excluir comentário
      await new Promise((resolve, reject) => {
        db.run("DELETE FROM comments WHERE id = ?", [commentId], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      res.json({ message: "Comentário rejeitado e removido com sucesso" });
    } catch (err) {
      console.error("Erro ao rejeitar comentário:", err);
      res.status(500).json({ error: "Erro interno do servidor" });
    }
  },
);

// Rotas de dashboard (apenas para admins)
app.get("/api/dashboard/stats", requireAdmin, async (req, res) => {
  try {
    const stats = await new Promise((resolve, reject) => {
      db.get(
        `SELECT
                 (SELECT COUNT(*) FROM posts) as total_posts,
                 (SELECT SUM(views) FROM posts) as total_views,
                 (SELECT COUNT(*) FROM comments WHERE is_approved = TRUE) as total_comments,
                 (SELECT COUNT(*) FROM users) as total_users`,
        [],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        },
      );
    });

    res.json(stats);
  } catch (err) {
    console.error("Erro ao buscar estatísticas:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota para obter usuários (apenas admin)
app.get("/api/users", requireAdmin, async (req, res) => {
  try {
    const users = await new Promise((resolve, reject) => {
      db.all(
        "SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC",
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        },
      );
    });
    res.json(users);
  } catch (err) {
    console.error("Erro ao buscar usuários:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota para atualizar status de admin
app.put("/api/users/:id/admin", requireAdmin, async (req, res) => {
  const userId = req.params.id;
  const { is_admin } = req.body;

  try {
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE users SET is_admin = ? WHERE id = ?",
        [is_admin, userId],
        function (err) {
          if (err) reject(err);
          else resolve(this);
        },
      );
    });
    res.json({ message: "Status de admin atualizado com sucesso" });
  } catch (err) {
    console.error("Erro ao atualizar status de admin:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota para deletar usuário
app.delete("/api/users/:id", requireAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    // Verificar se é o último admin
    const user = await new Promise((resolve, reject) => {
      db.get(
        "SELECT is_admin FROM users WHERE id = ?",
        [userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        },
      );
    });

    if (user.is_admin) {
      const adminCount = await new Promise((resolve, reject) => {
        db.get(
          "SELECT COUNT(*) as count FROM users WHERE is_admin = TRUE",
          (err, row) => {
            if (err) reject(err);
            else resolve(row.count);
          },
        );
      });

      if (adminCount <= 1) {
        return res
          .status(400)
          .json({ error: "Não é possível remover o último admin" });
      }
    }

    await new Promise((resolve, reject) => {
      db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    res.json({ message: "Usuário excluído com sucesso" });
  } catch (err) {
    console.error("Erro ao excluir usuário:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota para obter categorias
app.get("/api/categories", async (req, res) => {
  try {
    const categories = await new Promise((resolve, reject) => {
      db.all(
        `SELECT c.id, c.name, COUNT(pc.post_id) as post_count
                 FROM categories c
                 LEFT JOIN post_categories pc ON c.id = pc.category_id
                 GROUP BY c.id
                 ORDER BY c.name`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        },
      );
    });
    res.json(categories);
  } catch (err) {
    console.error("Erro ao buscar categorias:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota para criar categoria
app.post("/api/categories", requireAuth, async (req, res) => {
  const { name } = req.body;
  const userId = req.session.userId;

  if (!name) {
    return res.status(400).json({ error: "Nome da categoria é obrigatório" });
  }

  try {
    const result = await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO categories (name, created_by) VALUES (?, ?)",
        [name, userId],
        function (err) {
          if (err) reject(err);
          else resolve(this);
        },
      );
    });
    res.status(201).json({ id: result.lastID, name });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT") {
      return res.status(400).json({ error: "Categoria já existe" });
    }
    console.error("Erro ao criar categoria:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota para deletar categoria
app.delete("/api/categories/:id", requireAuth, async (req, res) => {
  const categoryId = req.params.id;
  const userId = req.session.userId;
  const isAdmin = req.session.isAdmin;

  try {
    // Primeiro verificar se a categoria existe e quem criou
    const category = await new Promise((resolve, reject) => {
      db.get(
        `SELECT id, created_by 
         FROM categories 
         WHERE id = ?`,
        [categoryId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!category) {
      return res.status(404).json({ error: "Categoria não encontrada" });
    }

    // Verificar se o usuário é o criador ou admin
    if (category.created_by !== userId && !isAdmin) {
      return res.status(403).json({ 
        error: "Apenas o criador da categoria ou administradores podem excluí-la" 
      });
    }

    // Se passar nas verificações, deletar a categoria
    await new Promise((resolve, reject) => {
      db.run("DELETE FROM categories WHERE id = ?", [categoryId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    
    res.json({ message: "Categoria excluída com sucesso" });
  } catch (err) {
    console.error("Erro ao excluir categoria:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Adicione esta rota adicional se precisar capturar sub-rotas
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Middleware para tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);

  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ error: "Token CSRF inválido" });
  }

  res.status(500).json({ error: "Erro interno do servidor" });
});

// Iniciar servidor
app.listen(config.port, () => {
  console.log(`Servidor BloggySource rodando na porta ${config.port}`);
});

// Fechar conexão com o banco de dados ao encerrar o servidor
process.on("SIGINT", () => {
  db.close();
  process.exit();
});
