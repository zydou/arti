# Arti Documentation Guide

## About the project

This project is built with Docusaurus, a modern static site generator.

## Local setup

To run this project locally, you need to have [Node.js](https://nodejs.org/en/download/) installed on your machine. Once you have Node.js installed, clone the repository and execute the following commands.

```bash
$ git clone https://gitlab.torproject.org/tpo/core/arti.git
$ cd arti/web
$ yarn install
$ yarn run build
```

These commands navigate into the project directory, install the docusaurus dependencies, and starts the website in a browser on the port `localhost:3000`.

## File structure

```bash
├── /docs # the docs content in markdown format
│   ├── intro.md
│   ├── example.md
├── /src # the css and js files for further customization
├── /static # static files like images
│   ├── /img
├── docusaurus.config.js # docusaurus website configuration file
├── babel.config.js # babel configuration file
├── package.json 
├── package-lock.json
├── sidebars.js # website's sidebar configuration file
└── .gitignore
```

## File naming

Use short and descriptive names for files in the `docs` directory, and ensure to stick to 1-3 words before the file extension. 

For example, `getting-started.md`

## Adding new content

To add a new file to the docs, 

1. Create a new `.md` file in the docs directory.
2. Start the file with needed meta, including the title, in the following format. 
    
    ```bash
    ---
    title: "Example file"
    ---
    ```
    
3. After adding the content to the file, update the `sidebars.js` file with your file’s name, following the existing structure. For example:
    
    ```jsx
    /** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
    const sidebars = {  
      artiSidebar: [
    		// to link an individual page
        {
          type: 'doc',
          label: 'Getting Started with Arti',
          id: 'getting-started'
        },
    		// to link a directory
    		{
          type: 'category',
          label: 'Example Category',
          items: ['example-category/intro', 'example-category/example']
        }
    	]
    };
    ```
[Watch video instructions](https://www.loom.com/share/3f10033a270a40afab3fb8c79830c86c?sid=263c4d7f-19cd-4324-b2dc-8357852de3e8) for adding new content.

## Making changes and updates

To make updates to the documentation, check out to a new branch from the main branch to update the most recent version of the documentation. After making changes, push your changes to the repository and open a merge request. 

Your MR will be assigned a reviewer, and will be merged after approval.
