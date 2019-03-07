'use strict';

const main = () => {
  const formElement = document.querySelector('form#search-tortilla');
  formElement.addEventListener('submit', handleFormSubmit);

  function handleFormSubmit (event) {
    event.preventDefault();
    const inputElement = event.target.querySelector('input');
    const inputValue = inputElement.value;

    searchTortillas(inputValue);
  }

  const searchTortillas = async (tortillaOwner) => {
    try {
      const tortillasRequest = await fetch(`/api/tortillas?username=${tortillaOwner}`);
      if (tortillasRequest.status === 404) {
        // Esto no
        const errorElement = document.querySelector('.error');
        errorElement.style.visibility = 'visible';
      }
      const tortillas = await tortillasRequest.json();
      const userListElement = document.querySelector('.user-list ul');
      tortillas.forEach(tortilla => {
        let node = document.createElement('li');
        let textnode = document.createTextNode(tortilla.name);
        node.appendChild(textnode);
        userListElement.appendChild(node);
      });
    } catch (error) {
      console.error(error);
    }
  };
};

window.addEventListener('load', main);
