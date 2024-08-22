import express, { Response, Request } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
const port = process.env.PORT;

const prisma = new PrismaClient();

app.use(express.json());

// Função para gerar token JWT
const generateToken = (userId: string) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET as string, {
    expiresIn: "1h",
  });
};

// Código que decodifica e valida o token de autenticação JWT
const authenticateToken = (req: Request, res: Response, next: () => void) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET as string, (err, user) => {
    if (err) return res.sendStatus(403);
    (req as any).user = user;
    next();
  });
};

// Rota de registro de usuário
app.post("/register", async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;
    const encryptedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: encryptedPassword,
      },
    });

    const token = generateToken(newUser.id.toString());

    res.status(201).json({ user: newUser, token });
  } catch (error) {
    res.status(400).json({ error: "Erro ao criar usuário" });
  }
});

// Rota de login
app.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const token = generateToken(user.id.toString());

    res.json({ user, token });
  } catch (error) {
    res.status(400).json({ error: "Erro ao fazer login" });
  }
});

// Rota para obter informações do usuário (protegida por token JWT)
app.get("/users", authenticateToken, async (req: Request, res: Response) => {
    try {
      const { userId } = (req as any).user;
  
      const user = await prisma.user.findUnique({
        where: { id: parseInt(userId) },
      });
  
      if (!user) {
        return res.status(404).json({ error: "Usuário não encontrado" });
      }
  
      res.json(user);
    } catch (error) {
      res.status(400).json({ error: "Erro ao buscar usuário" });
    }
  });  

// Rota para atualizar usuário (protegida por token JWT)
app.put("/users", authenticateToken, async (req: Request, res: Response) => {
  try {
    const { userId } = (req as any).user;
    const { name, email, password } = req.body;

    const encryptedPassword = await bcrypt.hash(password, 10);

    const updatedUser = await prisma.user.update({
      where: { id: parseInt(userId) },
      data: {
        name,
        email,
        password: encryptedPassword,
      },
    });

    res.json(updatedUser);
  } catch (error) {
    res.status(400).json({ error: "Erro ao atualizar usuário" });
  }
});

// Rota para deletar usuário (protegida por token JWT)
app.delete("/users", authenticateToken, async (req: Request, res: Response) => {
  try {
    const { userId } = (req as any).user;

    await prisma.user.delete({
      where: { id: parseInt(userId) },
    });

    res.sendStatus(204);
  } catch (error) {
    res.status(400).json({ error: "Erro ao deletar usuário" });
  }
});

app.listen(port, () => {
  console.log(`Rodando na porta ${port}!`);
});
