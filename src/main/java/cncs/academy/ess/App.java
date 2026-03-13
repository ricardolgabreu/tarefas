package cncs.academy.ess;

import cncs.academy.ess.controller.AuthorizationMiddleware;
import cncs.academy.ess.controller.TodoController;
import cncs.academy.ess.controller.TodoListController;
import cncs.academy.ess.controller.UserController;

import cncs.academy.ess.repository.TodoListsRepository;
import cncs.academy.ess.repository.TodoRepository;
import cncs.academy.ess.repository.UserRepository;

import cncs.academy.ess.repository.memory.InMemoryTodoRepository;
import cncs.academy.ess.repository.memory.InMemoryTodoListsRepository;
import cncs.academy.ess.repository.memory.InMemoryUserRepository;

import cncs.academy.ess.service.TodoListsService;
import cncs.academy.ess.service.TodoService;
import cncs.academy.ess.service.TodoUserService;

import io.javalin.Javalin;

import java.security.NoSuchAlgorithmException;

public class App {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(it -> it.anyHost());
            });
        }).start(7100);

        // -----------------------------
        // Repositórios em memória (sem BD)
        // -----------------------------
        UserRepository userRepository = new InMemoryUserRepository();
        TodoListsRepository listsRepository = new InMemoryTodoListsRepository();
        TodoRepository todoRepository = new InMemoryTodoRepository();

        // Services
        TodoUserService userService = new TodoUserService(userRepository);
        TodoListsService toDoListService = new TodoListsService(listsRepository);
        TodoService todoService = new TodoService(todoRepository, listsRepository);

        // Controllers
        UserController userController = new UserController(userService);
        TodoListController todoListController = new TodoListController(toDoListService);
        TodoController todoController = new TodoController(todoService, toDoListService);

        // Middleware
        AuthorizationMiddleware authMiddleware = new AuthorizationMiddleware(userRepository);

        // CORS headers (extra)
        app.before(ctx -> {
            ctx.header("Access-Control-Allow-Origin", "*");
            ctx.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            ctx.header("Access-Control-Allow-Headers", "*");
        });

        // Middleware de autorização
        app.before(authMiddleware::handle);

        // -----------------------------
        // Rotas
        // -----------------------------

        // Gestão de utilizadores
        app.post("/user", userController::createUser);
        app.get("/user/{userId}", userController::getUser);
        app.delete("/user/{userId}", userController::deleteUser);
        app.post("/login", userController::loginUser);

        // To do lists
        app.post("/todolist", todoListController::createTodoList);
        app.get("/todolist", todoListController::getAllTodoLists);
        app.get("/todolist/{listId}", todoListController::getTodoList);

        // To do items
        app.post("/todo/item", todoController::createTodoItem);
        app.get("/todo/{listId}/tasks", todoController::getAllTodoItems);
        app.get("/todo/{listId}/tasks/{taskId}", todoController::getTodoItem);
        app.delete("/todo/{listId}/tasks/{taskId}", todoController::deleteTodoItem);

        // -----------------------------
        // Dados dummy (opcional)
        // -----------------------------
        // Para Newman/Postman, normalmente é melhor começar "limpo"
        // e criar o user/list/task via requests.
        //
        // Mas se quiseres ter sempre 1 user/list/task automaticamente,
        // podes descomentar e adaptar:
        //
        // seed(userService, toDoListService, todoService);
    }

    // Exemplo opcional de seed em memória (se precisares)
    /*
    private static void seed(TodoUserService userService, TodoListsService listService, TodoService todoService) {
        var u = userService.register("admin", "123"); // depende do teu service
        var list = listService.createTodoList(u.getId(), "Demo"); // depende assinatura
        todoService.createTodoItem(list.getId(), "Buy milk"); // depende assinatura
    }
    */
}
