const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
  // Obtener la ruta del archivo solicitado
  const filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url);

  // Leer el archivo
  fs.readFile(filePath, (err, content) => {
    if (err) {
      // Si hay un error al leer el archivo, devolver un error 404
      res.writeHead(404);
      res.end('404 Not Found');
    } else {
      // Establecer el encabezado de respuesta y enviar el contenido del archivo
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(content, 'utf-8');
    }
  });
});

const PORT = process.env.PORT || 31459;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
