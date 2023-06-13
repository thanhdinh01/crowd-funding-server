require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs = require("fs");
const app = express();
app.use(express.json());
const verifyToken = require("./middleware/auth");
const rawdata = fs.readFileSync("db.json");
const database = JSON.parse(rawdata);
let users = database.users;
const cors = require("cors");
const corsOptions = {
  origin: "*",
  credentials: true, //access-control-allow-credentials:true
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
const generateTokens = (payload) => {
  const { id, name } = payload;
  const accessToken = jwt.sign({ id, name }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "30s",
  });
  const refreshToken = jwt.sign(
    { id, name },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: "48h",
    }
  );

  return { accessToken, refreshToken };
};
function updateRefreshToken(name, refreshToken) {
  console.log("updateRefreshToken ~ name", name);
  users = users.map((user) => {
    if (user.name === name) {
      return {
        ...user,
        refreshToken,
      };
    }
    return user;
  });
  fs.writeFile("db.json", JSON.stringify({ ...database, users }));
}
app.get("/me", verifyToken, (req, res) => {
  res.header("Access-Control-Allow-Origin", "*");
  fs.readFile("db.json", "utf8", (err, data) => {
    if (err) {
      return res.status(500).json({ message: "Error server" });
    }
    const db = JSON.parse(data);
    const user = db.users.find((user) => user.id === req.userId);
    if (!user) return res.sendStatus(401);
    res.json(user);
  });
  // const user = users.find((user) => {
  //   return user.id === req.userId;
  // });
  // if (!user) return res.sendStatus(401);
  // res.json(user);
});
app.post("/auth/login", (req, res) => {
  const email = req.body.email;
  fs.readFile("db.json", "utf8", (err, data) => {
    if (err) {
      return res.status(500).json({ message: "Error server" });
    }
    const db = JSON.parse(data);
    const user = db.users.find((user) => user.email === email);
    if (!user) return res.sendStatus(401);
    const dbPassword = user.password;
    bcrypt.compare(req.body.password, dbPassword, (err, hash) => {
      if (err || !hash) {
        res.status(403).json({
          statusCode: 403,
          error: {
            message: "Password does not match",
          },
        });
      }
      const tokens = generateTokens(user);

      updateRefreshToken(user.name, tokens.refreshToken);
      res.json(tokens);
    });
    res.json(user);
  });
  // const user = users.find((user) => {
  //   return user.email === email;
  // });
  // if (!user) return res.sendStatus(401);
  // const dbPassword = user.password;
  // bcrypt.compare(req.body.password, dbPassword, (err, hash) => {
  //   if (err || !hash) {
  //     res.status(403).json({
  //       statusCode: 403,
  //       error: {
  //         message: "Password does not match",
  //       },
  //     });
  //   }
  //   const tokens = generateTokens(user);

  //   updateRefreshToken(user.name, tokens.refreshToken);
  //   res.json(tokens);
  // });
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) return res.sendStatus(401);
  const user = users.find((user) => {
    return user.refreshToken === refreshToken;
  });
  if (!user) return res.sendStatus(403);
  try {
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const tokens = generateTokens(user);
    updateRefreshToken(user.name, tokens.refreshToken);
    res.json(tokens);
  } catch (err) {
    console.log(err);
    res.sendStatus(403);
  }
});

app.post("/auth/register", (req, res) => {
  console.log("users register 1", users);
  const { name, password, email, permissions } = req.body;
  // Đọc dữ liệu từ tệp db.json
  fs.readFile("db.json", "utf8", (err, data) => {
    if (err) {
      return res.status(500).json({ message: "Lỗi server" });
    }

    const db = JSON.parse(data);

    // Kiểm tra xem tên người dùng đã tồn tại chưa
    if (db.users.find((user) => user.email === email)) {
      return res.status(400).json({ message: "Tên người dùng đã tồn tại" });
    }

    // Hash mật khẩu
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        return res.status(500).json({ message: "Lỗi server" });
      }

      // Thêm người dùng mới vào tệp db.json
      db.users.push({
        id: users.length + 1,
        name,
        password: hash,
        email,
        refreshToken: null,
        permissions,
      });

      // Ghi dữ liệu vào tệp db.json
      fs.writeFile("db.json", JSON.stringify(db), "utf8", (err) => {
        if (err) {
          return res.status(500).json({ message: "Lỗi server" });
        }

        console.log("users register 2", db.users);
        res.json({ message: "Đăng ký thành công" });
      });
    });
  });
  // const user = users.find((user) => {
  //   return user.email === email;
  // });
  // if (user) {
  //   return res.sendStatus(409).json({ error: "User already exists" });
  // }

  // console.log("users register 2", users);
  // bcrypt.hash(password, 10, (err, hash) => {
  //   if (err) {
  //     return;
  //   }
  //   users.push({
  // id: users.length + 1,
  // name,
  // password: hash,
  // email,
  // refreshToken: null,
  // permissions,
  //   });
  //   console.log("users register 3", users);
  //   console.log("before writeFileSync");
  //   fs.writeFileSync("db.json", JSON.stringify({ ...database, users }));
  //   console.log("after writeFileSync");
  //   console.log("users register 4", users);
  //   res.sendStatus(201);
  // });
});

app.delete("/logout", verifyToken, (req, res) => {
  const user = users.find((user) => user.id === req.userId);
  updateRefreshToken(user.name, "");
  res.sendStatus(204);
});
app.get("/demo", (req, res) => {
  res.json({ message: "Hello from server" });
});
app.listen(5000, () => console.log("Server auth started on port 5000"));
