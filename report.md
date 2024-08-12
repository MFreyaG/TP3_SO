<!-- LTeX: language=pt-BR -->

# PAGINADOR DE MEMÓRIA -- RELATÓRIO

1. Termo de compromisso

    Ao entregar este documento preenchiso, os membros do grupo afirmam que todo o código desenvolvido para este trabalho é de autoria própria.  Exceto pelo material listado no item 3 deste relatório, os membros do grupo afirmam não ter copiado material da Internet nem ter obtido código de terceiros.

2. Membros do grupo e alocação de esforço

    Preencha as linhas abaixo com o nome e o email dos integrantes do grupo.  Substitua marcadores `XX` pela contribuição de cada membro do grupo no desenvolvimento do trabalho (os valores devem somar 100%).

    * Matheus Grandinetti Barbosa Lima <matheusgrandinetti@gmail.com> 50%
    * César de Paula Morais <cesarpmorais@hotmail.com> 50%

3. Referências bibliográficas

- Operating Systems: Three Easy Pieces, Remzi H. Arpaci-Dusseau and Andrea C. Arpaci-Dusseau, November, 2023 (Version 1.10)
- https://www.geeksforgeeks.org/paging-in-operating-system/
- https://chatgpt.com/
- EDs Iniciais baseadas na implementação do professor - https://gitlab.dcc.ufmg.br/cunha-dcc605/mempager-assignment/-/blob/master/src/pager.c 


4. Detalhes de implementação
    1. Descreva e justifique as estruturas de dados utilizadas em sua solução.
        As estruturas de dados usadas na solução, que podem ser encontradas no próprio arquivo pager.c, nos dão controle sobre as páginas, quadros e processos existentes, além de uma visão macro sobre o paginador em si. Tais EDS são inicializadas apropriadamente ao se iniciar o programa, na função pager_init.
        - frame_data_t: armazena informações sobre cada quadro de página na memória física. Ela contém o identificador de processo (pid), o número da página associada, o status de proteção (prot), e um indicador de se a página foi modificada (dirty);
        - page_data_t: armazena informações sobre cada página virtual de um processo. Ela guarda o bloco associado no disco (block), um indicador se a página foi escrita no disco (on_disk), e o quadro de página na memória física (frame);
        - proc_t: armazena informações sobre cada processo, incluindo o identificador de processo (pid), o número de páginas atualmente alocadas (npages), o número máximo de páginas que o processo pode ter (maxpages), e um array de page_data_t que armazena informações sobre todas as páginas do processo.
        - proc_t: Novamente, é a principal estrutura de dados que gerencia todo o sistema de paginação. Ela contém um mutex para garantir que o acesso ao paginador seja thread-safe, o número total de quadros e blocos, um ponteiro para a lista de quadros (frames), o número de quadros livres (frames_free), um ponteiro para a lista de processos (pid2proc), e um vetor que mapeia blocos para processos (block2pid). Além disso, mantém o ponteiro de relógio (clock) que é usado para implementar o algoritmo de substituição de página.

    2. Descreva o mecanismo utilizado para controle de acesso e modificação às páginas.
        O controle de acesso e modificação de páginas é feito utilizando três mecanismos:
        - Proteção de página: é o nível de permissão que o processo tem sobre a página. Inicialmente, o processo aloca uma página com permissão 0. Caso queira ler a posição de memória, o pager exclui os dados anteriores e altera a 'prot', e o mesmo ocorre com o write. Isso acontece para evitarmos overhead desnecessário (caso o processo não use a posição de memória alocada para leitura, por exemplo);
        - Algoritmo de Segunda Chance: Um ponteiro (clock) itera sobre os quadros de página. Se uma página estiver em uso (prot != PROT_NONE), a proteção é removida para dar uma "segunda chance" à página. Se, na próxima iteração, a página ainda não tiver sido acessada (a proteção já foi removida), a página é candidata a ser substituída. Se a página for substituída e estiver marcada como suja, ou seja, em uso por algum processo, ela é escrita no disco antes de ser removida da memória.
        - Mutex (pthread_mutex_t mutex): Para garantir que o paginador possa ser acessado por múltiplas threads de forma segura, um mutex é utilizado. Todas as funções que modificam o estado do paginador ou acessam estruturas compartilhadas, como pager_fault, pager_extend, e pager_release_and_get_frame, bloqueiam o mutex no início e o liberam no final. Isso previne condições de corrida e inconsistências no estado do sistema de memória.
