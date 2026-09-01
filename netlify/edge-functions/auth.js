// Candado de acceso privado para las rutas configuradas en netlify.toml.
// Pide usuario + contraseña (HTTP Basic Auth). Las credenciales se leen de
// variables de entorno definidas en Netlify:
//   PRIVATE_USER      -> usuario
//   PRIVATE_PASSWORD  -> contraseña (usa solo letras/números/símbolos ASCII)
//
// Para proteger una app nueva, agrega su ruta en netlify.toml (no hay que tocar este archivo).

export default async (request, context) => {
  const expectedUser = Netlify.env.get("PRIVATE_USER");
  const expectedPass = Netlify.env.get("PRIVATE_PASSWORD");

  // Si no hay credenciales configuradas, no bloquea (evita dejarte afuera por error de config).
  if (!expectedUser || !expectedPass) {
    return context.next();
  }

  const header = request.headers.get("authorization") || "";
  const [scheme, encoded] = header.split(" ");

  if (scheme === "Basic" && encoded) {
    let decoded = "";
    try {
      decoded = atob(encoded);
    } catch (_) {
      decoded = "";
    }
    const sep = decoded.indexOf(":");
    if (sep !== -1) {
      const user = decoded.slice(0, sep);
      const pass = decoded.slice(sep + 1);
      if (user === expectedUser && pass === expectedPass) {
        return context.next();
      }
    }
  }

  return new Response("Acceso privado. Se requiere autenticación.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Privado", charset="UTF-8"',
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
};
