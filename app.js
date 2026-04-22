const mysql = require('mysql2/promise')
require('dotenv').config()
const express = require('express')
const app = express()
const path = require('path')
const materias = ['matemática', 'física', 'PWEB', 'quimica', 'FSOR', 'POO']
const con = await mysql.createConnection({
    user: process.env.user,
    password: process.env.password,
    port: 3306,
    database: process.env.database
})
const bcrypt = require('bcrypt')
const login_nao_Necessario = ['/criar_conta', '/fazer_login'] // fazer depois
const jwt = require('jsonwebtoken')
const parser = require('cookie-parser')
app.use(parser())

// token de sessao vai te id, cpf e permissao
// aluno vai poder ver suas proprias notas e faltas
// nota e falta sao entidades com chave estrangeira (ID)
// professor pode colocar nota e inserir falta.
// registro -> feito
// login -> qse feito

app.use(async (req, res, next) => {
          if (login_nao_Necessario.includes(req.url) && req.cookies.sessao) {
            return res.status(403).send('não autorizado.')
          }
          let k = jwt.verify(req.cookies.sessao, process.env.chave)
          if (k.id && k.tipo) {
            let conn = await con
            let a = await conn.query(`SELECT * FROM usuarios WHERE id=? AND permissao=?`, [k.id, k.tipo]) // evitar fraude de permissao
            if (a[0].length === 0) {
                return res.status(401).send('não autorizado.')
            } else {
                return next()
            }
          } else {
            return res.status(401).send('não autorizado.')
          } 
        return next()
})

async function k() {
    let conn = await con
    app.use(express.static(path.join(__dirname, 'public')))
    app.use(express.json())

    //professor: cpf, senha, nome, id, email
    //aluno: cpf, senha, nome, id, email
    //esquece o de cima pq virou tudo a mesma entidade 'usuario'.
    //turma: qtd alunos, codigo
    //add nota, botar presença

//aqui vo coloca a resenha que o luiz pediu a nota la espero q funcione pq no meu funcionou mas voce sabe como e eessas coisa de tecnologia ne tipo so funciona quando quer :<
app.post('/nota', async (req, res) => {
    try {
    
        let token = jwt.verify(req.cookies.sessao, process.env.chave)

    
        if (token.permissao != 2) {
            return res.send("nao e profesor")
        }

        let id = req.body.id
        let materia = req.body.materia
        let nota = req.body.nota

        await con.query(
            "INSERT INTO notas (id, materia, nota) VALUES (?, ?, ?)",
            [id, materia, nota]
        )

        res.send("nota salva!!!!")
    } catch (err) {
        res.send("deu erro ;<")
    }
})


    app.post('/registro?tipo', async (req, res) => {
        let b = await bcrypt.hash(req.body.senha,10)
        try {
        let a = await conn.query(`INSERT INTO usuarios (cpf, email, nome, senha, permissao) VALUES (?,?,?,?)`, [req.body.cpf, req.body.email, req.body.nome, b, req.body.permissao])
        res.cookie('sessao', jwt.sign({
                    id: a[0].resultId,
                    cpf: req.body.cpf,
                    permissao: a[0][0].permissao
                }, process.env.chave), {
                    expires: true,
                    maxAge: 1000*60*60*24,
                    httpOnly: true
                })
        return res.send('usuário criado com sucesso')
        // isso aq funciona pq no banco de dados vai ser cpf unique e email unique; portanto isso vai retornar um erro se os dados nao forem unicos. + id é BIG INT PRIMARY KEY AUTO_INCREMENT entao
        // nao precisa inserir ele (id)
        } catch(err) {
            return res.status(400).send('dados inválidos; em uso ou mal formatados.')
        }
    })

    app.post('/login', async (req, res) => {
        let a = await conn.query('SELECT senha, id, permissao FROM usuarios WHERE cpf=?', [req.body.cpf])
        if (a[0].length === 0) {
            return res.status(401).send('usuário inexistente')
        }
        let a2 = bcrypt.compare(req.body.senha, a[0][0].senha)
            if (a2) {
                res.cookie('sessao', jwt.sign({
                    id: a[0][0].id,
                    cpf: req.body.cpf,
                    permissao: a[0][0].permissao
                }, process.env.chave), {
                    expires: true,
                    maxAge: 1000*60*60*24,
                    httpOnly: true
                })
                return res.send('usuário logado.')
            } else {
                return res.status(401).send('não autorizado.')
            }
    })

    app.get('/notas/:id', async (req, res) => {
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (req.params.id === 0) { // significa que o cliente pediu a própria nota.
            if (req.query.materia) {
                if (!materias.includes(req.query.materia)) {
                    return res.status(401).send('matéria inválida.')
                }
                let a = await conn.query('SELECT * FROM notas WHERE id_aluno=? AND materia=?', [k.id, req.query.materia]) 
                    return res.send(a[0])
            } else {
                let b =  await conn.query('SELECT * FROM notas WHERE id_aluno=?', [k.id])
                    return res.send(b[0])
            }
        } else {
            if (k.permissao === 2) { // só professor pode ver nota de outras pessoas
                if (req.query.materia) {
                    let a = await conn.query('SELECT * FROM notas WHERE id_aluno=? AND materia=?', [req.params.id, req.query.materia]) 
                        return res.send(a[0])
                }  else {  
                    let b =  await conn.query('SELECT * FROM notas WHERE id_aluno=?', [k.id])
                        return res.send(b[0])
                }
            } else {
                return res.status(403).send('não autorizado.')
            }
            
        }
        
    })

    app.get('/faltas/:id', async (req, res) => {
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (req.params.id === 0) { // significa que o cliente pediu as próprias faltas.
            if (req.query.materia) {
                if (!materias.includes(req.query.materia)) {
                        return res.status(401).send('matéria inválida.')
                }
                let a = await conn.query('SELECT * FROM faltas WHERE id_aluno=? AND materia=?', [k.id, req.query.materia]) 
                return res.send(a[0])
            } else {
                let b =  await conn.query('SELECT * FROM faltas WHERE id_aluno=?', [k.id])
                return res.send(b[0])
            }
        } else {
            if (k.permissao === 2) { // só professor pode ver falta de outras pessoas
                if (req.query.materia) {
                let a = await conn.query('SELECT * FROM faltas WHERE id_aluno=? AND materia=?', [req.params.id, req.query.materia]) 
                    return res.send(a[0])
                }  else {  
                let b =  await conn.query('SELECT * FROM faltas WHERE id_aluno=?', [k.id])
                    return res.send(b[0])
                }
            } else {
                return res.status(403).send('não autorizado.')
            }
            
        }
    })

    app.post("/faltas/:id", async (req, res)=>{
            let k = jwt.verify(req.cookies.sessao, process.env.chave)
            if(k.permissao === 2){
                try{
                    if(!materias.includes(req.body.materia)){
                        return res.status(400).send('matéria inexistente')
                    }
                    await conn.query("INSERT INTO faltas (id_aluno, materia, dia) WHERE  [?,?,?]", [req.body.id, req.body.materia, req.body.dia])
                    return res.send("Nota inserida com sucesso")
                }
                catch(erro){
                    return res.status(400).send(`Má formatação dos dados. Erro: ${erro}`)
                }
            }
            else{
                return res.status(403).send("acesso não autorizado")
            }
        })


    app.listen(8080, () => {
        console.log('servidor rodando em 8080')
    })


}

k()
