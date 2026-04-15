const mysql = require('mysql2/promise')
require('dotenv').config()
const express = require('express')
const app = express()
const path = require('path')
const con = await mysql.createConnection({
    user: process.env.user,
    password: process.env.password,
    port: 3306,
    database: process.env.database
})
const bcrypt = require('bcrypt')
const loginNecessario = ['/', '/notas', '/faltas'] // fazer depois
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
    if (loginNecessario.includes(req.url)) {
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
    } 
    return next()
})

async function k() {
    app.use(express.static(path.join(__dirname, 'public')))
    app.use(express.json())

    //professor: cpf, senha, nome, id, email
    //aluno: cpf, senha, nome, id, email
    //turma: qtd alunos
    //add nota, botar presença

    app.post('/registro?tipo', async (req, res) => {
        let conn = await con
        let b = await bcrypt.hash(req.body.senha,10)
        try {
        let a = await conn.query(`INSERT INTO usuarios (cpf, email, nome, senha) VALUES (?,?,?,?)`, [req.body.cpf, req.body.email, req.body.nome, b])
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
            return res.status(401).send('dados inválidos ou erro interno do servidor')
        }
    })

    app.post('/login', async (req, res) => {
        let conn = await con
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
        let conn = await con
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (req.params.id === 0) { // significa que o cliente pediu a própria nota.
        if (req.query.materia) {
            let a = await conn.query('SELECT * FROM notas WHERE id=? AND materia=?', [k.id, req.query.materia]) 
                return a[0]
        } else {
            let b =  await conn.query('SELECT * FROM notas WHERE id=?', [k.id])
                return b[0]
        }
        } else {
            if (k.permissao === 2) { // só professor pode ver nota de outras pessoas
                if (req.query.materia) {
                let a = await conn.query('SELECT * FROM notas WHERE id=? AND materia=?', [req.params.id, req.query.materia]) 
                    return a[0]
                }  else {  
                let b =  await conn.query('SELECT * FROM notas WHERE id=?', [k.id])
                    return b[0]
                }
            }
            
        }
        
    })

    app.get('/faltas/:id', async (req, res) => {
        let conn = await con
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (req.params.id === 0) { // significa que o cliente pediu as próprias faltas.
        if (req.query.materia) {
            let a = await conn.query('SELECT * FROM faltas WHERE id=? AND materia=?', [k.id, req.query.materia]) 
                return a[0]
        } else {
            let b =  await conn.query('SELECT * FROM faltas WHERE id=?', [k.id])
                return b[0]
        }
        } else {
            if (k.permissao === 2) { // só professor pode ver falta de outras pessoas
                if (req.query.materia) {
                let a = await conn.query('SELECT * FROM faltas WHERE id=? AND materia=?', [req.params.id, req.query.materia]) 
                    return a[0]
                }  else {  
                let b =  await conn.query('SELECT * FROM faltas WHERE id=?', [k.id])
                    return b[0]
                }
            }
            
        }
    })


    app.listen(8080, () => {
        console.log('servidor rodando em 8080')
    })


}

k()
