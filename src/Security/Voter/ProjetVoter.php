<?php

namespace App\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\User\UserInterface;
use App\Repository\ProjetRepository;
use App\Repository\TacheRepository;

class ProjetVoter extends Voter
{

    public function __construct(
        private ProjetRepository $projetRepository,
        private TacheRepository $tacheRepository,
    )
    {
        
    }
    protected function supports(string $attribute, mixed $subject): bool
    {   
        // On vérifie si l'attribut est 'acces_projet' ou 'acces_tache'
        return $attribute === 'acces_projet' || $attribute === 'acces_tache';
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        // Voter récupère un projet si c'est 'acces_projet', sinon une tâche
        if($attribute === 'acces_projet') {
            $projet = $this->projetRepository->find($subject);
        } else {
            $tache = $this->tacheRepository->find($subject);
            $projet = $tache?->getProjet();
        }

        // Récupère l'utilisateur connecté
        $user = $token->getUser();

        // Si l'utilisateur n'est pas connecté ou le projet n'existe pas on refuse l'accès
        if (!$user instanceof UserInterface || !$projet) {
            return false;
        }

        // Si l'utilisateur est admin ou que le projet contient l'utilisateur on autorise l'accès
        return $user->isAdmin() || $projet->getEmployes()->contains($user);
    }
}